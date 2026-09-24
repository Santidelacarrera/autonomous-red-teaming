"""FastAPI composition root with versioned, authenticated, proposal-only endpoints."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from hashlib import sha256
from time import perf_counter
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware

from art_sim.api.security import Authenticator, Principal
from art_sim.api.services import ApprovalService, SimulationService
from art_sim.domain.exceptions import (
    ApprovalRequiredError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
)
from art_sim.observability.telemetry import MetricsRegistry
from art_sim.platform.config import RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.platform.models import SimulationRun, SimulationRunStatus
from art_sim.platform.sqlite import OperationalStoreError
from art_sim.remediation.models import ApprovalDecision
from art_sim.security.audit import (
    InMemorySecurityAuditSink,
    NullSecurityAuditSink,
    SecurityAuditEvent,
    SecurityAuditSink,
    SecurityEventType,
)
from art_sim.security.config import SecuritySettings
from art_sim.security.permissions import Permission, authorize
from art_sim.security.rate_limit import (
    InMemoryRateLimiter,
    RateLimiter,
    RateLimitPolicy,
    UnlimitedRateLimiter,
)
from art_sim.security.sessions import SessionLifecycle, StatelessBearerSession


class CreateSimulationRequest(BaseModel):
    """Controlled scenario selection; arbitrary attack definitions are not accepted."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")


class ApprovalRequest(BaseModel):
    """One human decision; backend CAS controls all state transitions."""

    model_config = ConfigDict(extra="forbid")

    decision: ApprovalDecision


class ApiError(BaseModel):
    """Stable safe error envelope shared by expected failures."""

    code: str
    message: str
    request_id: str


def _run_response(run: SimulationRun) -> dict[str, object]:
    """Serialize only the public, secret-free SimulationRun contract."""
    return run.model_dump(mode="json")


def create_app(
    simulation_service: SimulationService,
    approval_service: ApprovalService,
    health_service: HealthService,
    authenticator: Authenticator,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[None]] | None = None,
    *,
    security_settings: SecuritySettings | None = None,
    rate_limiter: RateLimiter | None = None,
    security_audit: SecurityAuditSink | None = None,
    security_metrics: MetricsRegistry | None = None,
    session_lifecycle: SessionLifecycle | None = None,
) -> FastAPI:
    """Compose the HTTP layer entirely from injected application services."""
    security = security_settings or SecuritySettings()
    if getattr(authenticator, "provider_kind", None) != security.authentication_provider.value:
        raise ConfigurationError("Configured authentication provider does not match its adapter")
    if security.environment is RuntimeEnvironment.PRODUCTION:
        if rate_limiter is None or isinstance(rate_limiter, InMemoryRateLimiter):
            raise ConfigurationError("Production requires a shared rate limiter")
        if security_audit is None or isinstance(security_audit, InMemorySecurityAuditSink):
            raise ConfigurationError("Production requires a durable security audit sink")
    limiter = rate_limiter or UnlimitedRateLimiter()
    audit = security_audit or NullSecurityAuditSink()
    metrics = security_metrics or MetricsRegistry()
    sessions = session_lifecycle or StatelessBearerSession()
    app = FastAPI(title="Autonomous Red Teaming Simulator API", version="1.0.0", lifespan=lifespan)
    if security.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(security.cors_allowed_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
            expose_headers=["X-Request-ID", "X-Response-Time-Ms", "Retry-After"],
            max_age=600,
        )

    @app.middleware("http")
    async def request_correlation(request: Request, call_next: RequestResponseEndpoint) -> Response:
        candidate = request.headers.get("X-Request-ID")
        request_id = candidate if candidate and len(candidate) <= 64 and candidate.replace("-", "").isalnum() else str(uuid4())
        request.state.request_id = request_id
        content_length = request.headers.get("content-length")
        if content_length is not None and content_length.isdigit() and int(content_length) > 65_536:
            response: Response = JSONResponse(
                status_code=413,
                content={"error": {"code": "REQUEST_TOO_LARGE", "message": "Request exceeds the API body limit", "request_id": request_id}},
            )
        else:
            started = perf_counter()
            response = await call_next(request)
            response.headers["X-Response-Time-Ms"] = f"{(perf_counter() - started) * 1000.0:.2f}"
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Frame-Options"] = "DENY"
        if security.hsts_enabled:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    def error(
        request: Request,
        status: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> JSONResponse:
        return JSONResponse(status_code=status, headers=headers, content={"error": ApiError(code=code, message=message, request_id=request.state.request_id).model_dump()})

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, _: RequestValidationError) -> JSONResponse:
        return error(request, 422, "INVALID_REQUEST", "Request validation failed")

    @app.exception_handler(OperationalStoreError)
    async def store_error(request: Request, exc: OperationalStoreError) -> JSONResponse:
        return error(request, 404 if "does not exist" in str(exc) else 409, "RUN_NOT_FOUND" if "does not exist" in str(exc) else "RUN_CONFLICT", "Simulation run is unavailable")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code = (
            "AUTHENTICATION_REQUIRED"
            if exc.status_code == 401
            else "FORBIDDEN"
            if exc.status_code == 403
            else "RATE_LIMIT_EXCEEDED"
            if exc.status_code == 429
            else "API_REQUEST_REJECTED"
        )
        message = (
            "Authentication is required."
            if exc.status_code == 401
            else "You do not have permission to perform this action."
            if exc.status_code == 403
            else "Request rate limit exceeded."
            if exc.status_code == 429
            else "Request cannot be completed"
        )
        return error(request, exc.status_code, code, message, dict(exc.headers or {}))

    async def emit(
        request: Request,
        event_type: SecurityEventType,
        result: str,
        identity: Principal | None = None,
        run_id: UUID | None = None,
    ) -> None:
        await audit.append(
            SecurityAuditEvent(
                event_type=event_type,
                subject=identity.subject if identity else None,
                issuer=identity.issuer if identity else None,
                request_id=request.state.request_id,
                run_id=run_id,
                result=result,
            )
        )

    async def limit(request: Request, key: str, policy: RateLimitPolicy) -> None:
        if not security.rate_limit_enabled:
            return
        decision = await limiter.consume(key, policy)
        if not decision.allowed:
            metrics.increment("rate_limit_exceeded_total")
            await emit(request, SecurityEventType.RATE_LIMIT_EXCEEDED, "limited")
            raise HTTPException(status_code=429, headers={"Retry-After": str(decision.retry_after_seconds)})

    async def principal(request: Request, authorization: str | None = Header(default=None)) -> Principal:
        host = request.client.host if request.client else "unknown"
        network_key = sha256(host.encode("utf-8")).hexdigest()[:24]
        await limit(
            request,
            network_key,
            RateLimitPolicy("authentication", security.auth_requests_per_minute),
        )
        try:
            identity = await authenticator.authenticate(authorization)
        except (AuthenticationError, PermissionError) as exc:
            metrics.increment("authentication_failure_total")
            await emit(request, SecurityEventType.AUTHENTICATION_FAILURE, "failed")
            raise HTTPException(status_code=401, detail="Authentication is required") from exc
        metrics.increment("authentication_success_total")
        await emit(request, SecurityEventType.AUTHENTICATION_SUCCESS, "succeeded", identity)
        return identity

    def require(permission: Permission) -> Callable[..., Awaitable[Principal]]:
        async def dependency(request: Request, identity: Principal = Depends(principal)) -> Principal:  # noqa: B008
            try:
                authorize(identity, permission)
            except AuthorizationError:
                metrics.increment("authorization_denied_total")
                await emit(request, SecurityEventType.AUTHORIZATION_DENIED, "denied", identity)
                raise HTTPException(status_code=403, detail="Authorization is insufficient")
            return identity
        return dependency

    @app.get("/health", tags=["health"])
    async def health() -> dict[str, object]:
        return (await health_service.health()).model_dump()

    @app.get("/readiness", tags=["health"])
    async def readiness(response: Response) -> dict[str, object]:
        result = await health_service.readiness()
        if result.status != "ok":
            response.status_code = 503
        return result.model_dump()

    @app.get("/api/v1/identity", tags=["identity"])
    async def current_identity(
        identity: Principal = Depends(require(Permission.SIMULATION_READ)),  # noqa: B008
    ) -> dict[str, object]:
        return identity.model_dump(mode="json")

    @app.post("/api/v1/logout", status_code=204, tags=["identity"])
    async def logout(
        request: Request,
        identity: Principal = Depends(require(Permission.SIMULATION_READ)),  # noqa: B008
    ) -> Response:
        await sessions.logout(identity)
        await emit(request, SecurityEventType.LOGOUT, "succeeded", identity)
        return Response(status_code=204)

    @app.post("/api/v1/simulations", status_code=202, tags=["simulations"])
    async def create_simulation(
        request: Request,
        body: CreateSimulationRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        identity: Principal = Depends(require(Permission.SIMULATION_CREATE)),  # noqa: B008
    ) -> dict[str, object]:
        await limit(request, identity.subject, RateLimitPolicy("simulation_create", security.simulation_creates_per_minute))
        try:
            run, created = await simulation_service.create(body.scenario_id, identity.subject, idempotency_key)
            await emit(request, SecurityEventType.SIMULATION_CREATED, "succeeded", identity, run.run_id)
            return {**_run_response(run), "created": created}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Scenario is not configured") from exc

    @app.get("/api/v1/scenarios", tags=["scenarios"])
    async def scenarios(_: Principal = Depends(require(Permission.SIMULATION_READ))) -> dict[str, object]:  # noqa: B008
        return {"items": [{"scenario_id": scenario_id} for scenario_id in simulation_service.scenarios()]}

    @app.get("/api/v1/simulations", tags=["simulations"])
    async def list_simulations(
        limit: int = 50,
        offset: int = 0,
        status: SimulationRunStatus | None = None,
        _: Principal = Depends(require(Permission.SIMULATION_READ)),  # noqa: B008
    ) -> dict[str, object]:
        if not 1 <= limit <= 200 or offset < 0:
            raise HTTPException(status_code=422, detail="Pagination is invalid")
        runs = await simulation_service.list(limit, offset, status)
        return {"items": [_run_response(run) for run in runs], "limit": limit, "offset": offset}

    @app.get("/api/v1/simulations/{run_id}", tags=["simulations"])
    async def get_simulation(
        run_id: UUID,
        _: Principal = Depends(require(Permission.SIMULATION_READ)),  # noqa: B008
    ) -> dict[str, object]:
        return _run_response(await simulation_service.get(str(run_id)))

    @app.post("/api/v1/simulations/{run_id}/approval", tags=["approval"])
    async def approve(
        request: Request,
        run_id: UUID,
        body: ApprovalRequest,
        identity: Principal = Depends(principal),  # noqa: B008
    ) -> dict[str, object]:
        permission = Permission.SIMULATION_APPROVE if body.decision is ApprovalDecision.APPROVED else Permission.SIMULATION_REJECT
        try:
            authorize(identity, permission)
        except AuthorizationError as exc:
            metrics.increment("authorization_denied_total")
            metrics.increment("approval_denied_total")
            await emit(request, SecurityEventType.AUTHORIZATION_DENIED, "denied", identity, run_id)
            raise HTTPException(status_code=403, detail="Authorization is insufficient") from exc
        if security.mfa_required_for_sensitive_actions and not identity.authentication.mfa_satisfied:
            metrics.increment("approval_denied_total")
            await emit(request, SecurityEventType.AUTHORIZATION_DENIED, "denied", identity, run_id)
            raise HTTPException(status_code=403, detail="Step-up authentication is required")
        await limit(request, identity.subject, RateLimitPolicy("approval", security.approval_requests_per_minute))
        try:
            approved_run = await approval_service.decide(str(run_id), body.decision, identity.subject)
            event_type = SecurityEventType.APPROVAL_APPROVED if body.decision is ApprovalDecision.APPROVED else SecurityEventType.APPROVAL_REJECTED
            await emit(request, event_type, "succeeded", identity, run_id)
            return _run_response(approved_run)
        except ApprovalRequiredError as exc:
            raise HTTPException(status_code=409, detail="Approval state conflicts with this request") from exc

    @app.get("/api/v1/simulations/{run_id}/risk", tags=["analysis"])
    async def risk(
        run_id: UUID,
        _: Principal = Depends(require(Permission.RISK_READ)),  # noqa: B008
    ) -> dict[str, object]:
        run = await simulation_service.get(str(run_id))
        return {"risk_before": run.risk_before, "risk_after": run.risk_after, "risk_delta": None if run.risk_before is None or run.risk_after is None else run.risk_before - run.risk_after}

    async def results_unavailable(run_id: UUID) -> None:
        """Ensure the run exists, then avoid inventing analysis that has not been persisted."""
        await simulation_service.get(str(run_id))
        raise HTTPException(status_code=409, detail="Simulation results are not yet persisted")

    @app.get("/api/v1/simulations/{run_id}/attack-paths", tags=["analysis"])
    async def attack_paths(run_id: UUID, _: Principal = Depends(require(Permission.ATTACK_PATH_READ))) -> None:  # noqa: B008
        await results_unavailable(run_id)

    @app.get("/api/v1/simulations/{run_id}/blast-radius", tags=["analysis"])
    async def blast_radius(run_id: UUID, _: Principal = Depends(require(Permission.BLAST_RADIUS_READ))) -> None:  # noqa: B008
        await results_unavailable(run_id)

    @app.get("/api/v1/simulations/{run_id}/remediations", tags=["remediation"])
    async def remediations(run_id: UUID, _: Principal = Depends(require(Permission.REMEDIATION_READ))) -> None:  # noqa: B008
        await results_unavailable(run_id)

    @app.get("/api/v1/simulations/{run_id}/verification", tags=["verification"])
    async def verification(run_id: UUID, _: Principal = Depends(require(Permission.VERIFICATION_READ))) -> None:  # noqa: B008
        await results_unavailable(run_id)

    @app.get("/api/v1/simulations/{run_id}/report", tags=["reports"])
    async def report(run_id: UUID, format: str = "markdown", _: Principal = Depends(require(Permission.REPORT_READ))) -> None:  # noqa: B008
        if format != "markdown":
            raise HTTPException(status_code=422, detail="Only markdown reports are supported")
        await results_unavailable(run_id)

    @app.get("/api/v1/security/status", tags=["security"])
    async def security_status(
        request: Request,
        identity: Principal = Depends(require(Permission.SECURITY_ADMIN)),  # noqa: B008
    ) -> dict[str, object]:
        await limit(request, identity.subject, RateLimitPolicy("admin", security.admin_requests_per_minute))
        await emit(request, SecurityEventType.ADMIN_READ, "succeeded", identity)
        return {
            "environment": security.environment.value,
            "authentication_provider": security.authentication_provider.value,
            "mfa_required_for_sensitive_actions": security.mfa_required_for_sensitive_actions,
            "rate_limiting": "enabled" if security.rate_limit_enabled else "disabled",
            "audit_logging": "configured" if not isinstance(audit, NullSecurityAuditSink) else "not_configured",
            "cors_origins_configured": len(security.cors_allowed_origins),
            "recent_events": [event.model_dump(mode="json") for event in await audit.recent(limit=20)],
            "metrics": metrics.snapshot(),
        }

    return app
