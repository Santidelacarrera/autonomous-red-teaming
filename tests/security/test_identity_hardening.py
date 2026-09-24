"""Phase 10.2 regressions for trusted MFA and fail-closed production composition."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar
from uuid import UUID, uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from pydantic import SecretStr

from art_sim.api.app import create_app
from art_sim.api.production import create_production_app
from art_sim.api.services import ApprovalService, ScenarioCatalog, SimulationService
from art_sim.domain.exceptions import ConfigurationError
from art_sim.observability.sink import (
    MetricEvent,
    TelemetryCapability,
)
from art_sim.platform.config import OperationalSettings, RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.platform.ports import OperationalStoreCapability
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import (
    AuditDurability,
    InMemorySecurityAuditSink,
    SecurityAuditEvent,
    SecurityEventType,
)
from art_sim.security.config import AuthenticationProviderKind, SecuritySettings
from art_sim.security.providers.development import DevelopmentHeaderAuthenticator
from art_sim.security.providers.oidc import OidcIdentityProvider, OidcSettings
from art_sim.security.rate_limit import (
    InMemoryRateLimiter,
    RateLimitDecision,
    RateLimiterScope,
    RateLimitPolicy,
)
from art_sim.security.secrets import EnvironmentSecretProvider, SecretProviderCapability
from art_sim.worker.jobs import CancellationReceipt, DispatchReceipt
from art_sim.worker.ports import DispatcherScope


async def _healthy() -> None:
    """Provide a deterministic readiness probe."""


class _Issuer:
    """Local cryptographic issuer fixture; it does not emulate a remote IdP."""

    def __init__(self) -> None:
        self.issuer = "https://identity.example.com"
        self.audience = "art-sim"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-one"
        self.jwks = {"keys": [self._public_jwk(self.private_key, self.kid)]}
        self.jwks_requests = 0

    @staticmethod
    def _public_jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
        value = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
        value["kid"] = kid
        value["use"] = "sig"
        value["alg"] = "RS256"
        return value

    def settings(self, *, mfa: bool = True) -> OidcSettings:
        """Return the exact public resource-server contract used by this issuer."""
        return OidcSettings(
            issuer=self.issuer,
            audience=self.audience,
            jwks_url=f"{self.issuer}/.well-known/jwks.json",
            mfa_claim="amr" if mfa else None,
            mfa_values=frozenset({"mfa"}) if mfa else frozenset(),
        )

    def token(
        self,
        *,
        roles: tuple[str, ...] = ("operator",),
        mfa_value: object = ("pwd", "mfa"),
        overrides: dict[str, Any] | None = None,
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = None,
        algorithm: str = "RS256",
    ) -> str:
        """Sign a bounded fixture token, optionally omitting the configured MFA claim."""
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "oidc-user",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "roles": list(roles),
        }
        if mfa_value is not None:
            claims["amr"] = mfa_value
        claims.update(overrides or {})
        return jwt.encode(
            claims,
            key or self.private_key,
            algorithm=algorithm,
            headers={"kid": kid or self.kid},
        )

    def provider(self, settings: OidcSettings | None = None) -> OidcIdentityProvider:
        """Build the real verifier over a deterministic JWKS transport."""

        async def handler(_: httpx.Request) -> httpx.Response:
            self.jwks_requests += 1
            return httpx.Response(200, json=self.jwks)

        return OidcIdentityProvider(
            settings or self.settings(),
            httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )


async def _oidc_client(
    tmp_path: Path,
    issuer: _Issuer,
) -> tuple[TestClient, SqliteOperationalStore, InMemorySecurityAuditSink]:
    store = SqliteOperationalStore(tmp_path / "oidc-security.sqlite3")
    await store.initialize()
    audit = InMemorySecurityAuditSink()
    settings = SecuritySettings(
        environment=RuntimeEnvironment.STAGING,
        authentication_provider=AuthenticationProviderKind.OIDC,
        oidc=issuer.settings(),
        mfa_required_for_sensitive_actions=True,
    )
    app = create_app(
        SimulationService(store, ScenarioCatalog(("shadow-demo",))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        issuer.provider(settings.oidc),
        security_settings=settings,
        rate_limiter=InMemoryRateLimiter(),
        security_audit=audit,
    )
    return TestClient(app), store, audit


async def _waiting_run(
    client: TestClient,
    store: SqliteOperationalStore,
    token: str,
) -> UUID:
    created = client.post(
        "/api/v1/simulations",
        headers={"Authorization": f"Bearer {token}"},
        json={"scenario_id": "shadow-demo"},
    )
    assert created.status_code == 202
    run_id = UUID(created.json()["run_id"])
    claim = await store.acquire_execution(run_id, "security-test", UUID(int=1))
    assert claim is not None
    await store.mark_waiting_approval(run_id, "security-test", claim.fencing_token)
    return run_id


async def test_approval_with_required_verified_mfa_is_allowed(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, store, _ = await _oidc_client(tmp_path, issuer)
    token = issuer.token()
    run_id = await _waiting_run(client, store, token)
    response = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "approved"},
    )
    assert response.status_code == 200


async def test_approval_with_required_missing_mfa_is_denied(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, store, audit = await _oidc_client(tmp_path, issuer)
    token = issuer.token(mfa_value=None)
    run_id = await _waiting_run(client, store, token)
    response = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "approved"},
    )
    assert response.status_code == 403
    assert SecurityEventType.MFA_FAILURE in {event.event_type for event in await audit.recent()}


async def test_approval_with_required_invalid_mfa_is_denied(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, store, _ = await _oidc_client(tmp_path, issuer)
    token = issuer.token(mfa_value=("pwd", "untrusted-value"))
    run_id = await _waiting_run(client, store, token)
    response = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "approved"},
    )
    assert response.status_code == 403


async def test_arbitrary_header_cannot_activate_mfa(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, store, _ = await _oidc_client(tmp_path, issuer)
    token = issuer.token(mfa_value=None)
    run_id = await _waiting_run(client, store, token)
    response = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers={"Authorization": f"Bearer {token}", "X-MFA-Verified": "true"},
        json={"decision": "approved"},
    )
    assert response.status_code == 403


async def test_request_body_cannot_activate_mfa(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, store, _ = await _oidc_client(tmp_path, issuer)
    token = issuer.token(mfa_value=None)
    run_id = await _waiting_run(client, store, token)
    response = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "approved", "mfa_satisfied": True},
    )
    assert response.status_code == 422


async def test_viewer_cannot_approve_even_with_verified_mfa(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, store, _ = await _oidc_client(tmp_path, issuer)
    operator = issuer.token()
    viewer = issuer.token(roles=("viewer",))
    run_id = await _waiting_run(client, store, operator)
    response = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers={"Authorization": f"Bearer {viewer}"},
        json={"decision": "approved"},
    )
    assert response.status_code == 403


async def test_valid_oidc_jwt_is_accepted_by_api(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, _, _ = await _oidc_client(tmp_path, issuer)
    response = client.get(
        "/api/v1/identity",
        headers={"Authorization": f"Bearer {issuer.token()}"},
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": datetime.now(UTC) - timedelta(minutes=5)},
        {"iss": "https://attacker.example.com"},
        {"aud": "another-api"},
    ],
    ids=("expired", "wrong-issuer", "wrong-audience"),
)
async def test_invalid_oidc_claims_receive_401(
    tmp_path: Path,
    overrides: dict[str, Any],
) -> None:
    issuer = _Issuer()
    client, _, _ = await _oidc_client(tmp_path, issuer)
    response = client.get(
        "/api/v1/identity",
        headers={"Authorization": f"Bearer {issuer.token(overrides=overrides)}"},
    )
    assert response.status_code == 401


async def test_prohibited_oidc_algorithm_receives_401(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, _, _ = await _oidc_client(tmp_path, issuer)
    response = client.get(
        "/api/v1/identity",
        headers={"Authorization": f"Bearer {issuer.token(algorithm='RS384')}"},
    )
    assert response.status_code == 401


async def test_unknown_oidc_kid_receives_401(tmp_path: Path) -> None:
    issuer = _Issuer()
    client, _, _ = await _oidc_client(tmp_path, issuer)
    response = client.get(
        "/api/v1/identity",
        headers={"Authorization": f"Bearer {issuer.token(kid='unknown')}"},
    )
    assert response.status_code == 401


async def test_jwks_rotation_refreshes_and_accepts_new_key() -> None:
    issuer = _Issuer()
    provider = issuer.provider()
    first = await provider.validate_token(issuer.token())
    assert first.subject == "oidc-user"

    rotated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated_kid = "key-two"
    issuer.jwks = {"keys": [issuer._public_jwk(rotated_key, rotated_kid)]}
    rotated = issuer.token(key=rotated_key, kid=rotated_kid)
    second = await provider.validate_token(rotated)
    assert second.subject == "oidc-user"
    assert issuer.jwks_requests == 2


async def test_unconfigured_mfa_claim_never_grants_assurance() -> None:
    issuer = _Issuer()
    identity = await issuer.provider(issuer.settings(mfa=False)).validate_token(issuer.token())
    assert not identity.authentication.mfa_satisfied


def test_required_oidc_mfa_without_claim_contract_fails_closed() -> None:
    issuer = _Issuer()
    with pytest.raises(ValueError, match="MFA"):
        SecuritySettings(
            environment=RuntimeEnvironment.PRODUCTION,
            authentication_provider=AuthenticationProviderKind.OIDC,
            oidc=issuer.settings(mfa=False),
            cors_allowed_origins=("https://command.example.com",),
            hsts_enabled=True,
            mfa_required_for_sensitive_actions=True,
        )


class _DistributedLimiter:
    deployment_scope: ClassVar[RateLimiterScope] = RateLimiterScope.DISTRIBUTED

    async def consume(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        del key, policy
        return RateLimitDecision(True)


class _DistributedDispatcher:
    deployment_scope: ClassVar[DispatcherScope] = DispatcherScope.DISTRIBUTED

    async def dispatch(self, run_id: UUID) -> DispatchReceipt:
        return DispatchReceipt(run_id=run_id, message_id=uuid4(), accepted=True)

    async def cancel(self, run_id: UUID) -> CancellationReceipt:
        return CancellationReceipt(run_id=run_id, accepted=True)


class _ProcessDispatcher:
    deployment_scope: ClassVar[DispatcherScope] = DispatcherScope.PROCESS

    async def dispatch(self, run_id: UUID) -> DispatchReceipt:
        return DispatchReceipt(run_id=run_id, message_id=uuid4(), accepted=True)

    async def cancel(self, run_id: UUID) -> CancellationReceipt:
        return CancellationReceipt(run_id=run_id, accepted=True)


class _DurableAudit:
    durability: ClassVar[AuditDurability] = AuditDurability.DURABLE

    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def append(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        return tuple(reversed(self.events[-limit:]))


class _SecretProvider:
    deployment_capability: ClassVar[SecretProviderCapability] = (
        SecretProviderCapability.EXTERNAL
    )

    async def get_secret(self, name: str) -> SecretStr:
        del name
        return SecretStr("a-secure-test-secret-with-32-bytes-minimum")


class _ShortSecretProvider(_SecretProvider):
    async def get_secret(self, name: str) -> SecretStr:
        del name
        return SecretStr("too-short")


class _ServerStore(SqliteOperationalStore):
    """Test double declaring server semantics; it is not a PostgreSQL adapter."""

    deployment_capability: ClassVar[OperationalStoreCapability] = (
        OperationalStoreCapability.SERVER_GRADE
    )


class _ExternalTelemetry:
    deployment_capability: ClassVar[TelemetryCapability] = TelemetryCapability.EXTERNAL

    async def emit_metric(self, event: MetricEvent) -> None:
        del event

    async def emit_trace(self, event: Any) -> None:
        del event


def _production_settings(issuer: _Issuer) -> SecuritySettings:
    return SecuritySettings(
        environment=RuntimeEnvironment.PRODUCTION,
        authentication_provider=AuthenticationProviderKind.OIDC,
        oidc=issuer.settings(),
        cors_allowed_origins=("https://command.example.com",),
        hsts_enabled=True,
        mfa_required_for_sensitive_actions=True,
    )


def _operational_settings(tmp_path: Path) -> OperationalSettings:
    return OperationalSettings(
        environment=RuntimeEnvironment.PRODUCTION,
        operational_database=tmp_path / "production.sqlite3",
    )


def test_production_rejects_development_authenticator(tmp_path: Path) -> None:
    issuer = _Issuer()
    with pytest.raises(ConfigurationError, match="OIDC"):
        create_production_app(
            authenticator=DevelopmentHeaderAuthenticator(enabled=True),  # type: ignore[arg-type]
            rate_limiter=_DistributedLimiter(),
            security_audit=_DurableAudit(),
            secret_provider=_SecretProvider(),
            store=_ServerStore(tmp_path / "production.sqlite3"),
            dispatcher=_DistributedDispatcher(),
            security_settings=_production_settings(issuer),
            operational_settings=_operational_settings(tmp_path),
            scenario_ids=("shadow-demo",),
        )


def test_production_rejects_in_memory_rate_limiter(tmp_path: Path) -> None:
    issuer = _Issuer()
    with pytest.raises(ConfigurationError, match="shared rate limiter"):
        create_production_app(
            authenticator=issuer.provider(),
            rate_limiter=InMemoryRateLimiter(),  # type: ignore[arg-type]
            security_audit=_DurableAudit(),
            secret_provider=_SecretProvider(),
            store=SqliteOperationalStore(tmp_path / "production.sqlite3"),
            dispatcher=_DistributedDispatcher(),
            security_settings=_production_settings(issuer),
            operational_settings=_operational_settings(tmp_path),
            scenario_ids=("shadow-demo",),
        )


def test_production_rejects_in_memory_audit_sink(tmp_path: Path) -> None:
    issuer = _Issuer()
    with pytest.raises(ConfigurationError, match="durable"):
        create_production_app(
            authenticator=issuer.provider(),
            rate_limiter=_DistributedLimiter(),
            security_audit=InMemorySecurityAuditSink(),  # type: ignore[arg-type]
            secret_provider=_SecretProvider(),
            store=SqliteOperationalStore(tmp_path / "production.sqlite3"),
            dispatcher=_DistributedDispatcher(),
            security_settings=_production_settings(issuer),
            operational_settings=_operational_settings(tmp_path),
            scenario_ids=("shadow-demo",),
        )


def test_production_rejects_process_local_dispatcher(tmp_path: Path) -> None:
    issuer = _Issuer()
    with pytest.raises(ConfigurationError, match="distributed simulation dispatcher"):
        create_production_app(
            authenticator=issuer.provider(),
            rate_limiter=_DistributedLimiter(),
            security_audit=_DurableAudit(),
            secret_provider=_SecretProvider(),
            store=_ServerStore(tmp_path / "production.sqlite3"),
            dispatcher=_ProcessDispatcher(),  # type: ignore[arg-type]
            security_settings=_production_settings(issuer),
            operational_settings=_operational_settings(tmp_path),
            scenario_ids=("shadow-demo",),
        )


def test_production_rejects_single_node_sqlite_store(tmp_path: Path) -> None:
    issuer = _Issuer()
    with pytest.raises(ConfigurationError, match="server-grade operational store"):
        create_production_app(
            authenticator=issuer.provider(),
            rate_limiter=_DistributedLimiter(),
            security_audit=_DurableAudit(),
            secret_provider=_SecretProvider(),
            store=SqliteOperationalStore(tmp_path / "production.sqlite3"),
            dispatcher=_DistributedDispatcher(),
            security_settings=_production_settings(issuer),
            operational_settings=_operational_settings(tmp_path),
            scenario_ids=("shadow-demo",),
        )


def test_production_rejects_environment_secret_provider(tmp_path: Path) -> None:
    issuer = _Issuer()
    with pytest.raises(ConfigurationError, match="external secret provider"):
        create_production_app(
            authenticator=issuer.provider(),
            rate_limiter=_DistributedLimiter(),
            security_audit=_DurableAudit(),
            secret_provider=EnvironmentSecretProvider(),  # type: ignore[arg-type]
            store=_ServerStore(tmp_path / "production.sqlite3"),
            dispatcher=_DistributedDispatcher(),
            telemetry=_ExternalTelemetry(),
            security_settings=_production_settings(issuer),
            operational_settings=_operational_settings(tmp_path),
            scenario_ids=("shadow-demo",),
        )


def test_production_rejects_missing_external_telemetry(tmp_path: Path) -> None:
    issuer = _Issuer()
    with pytest.raises(ConfigurationError, match="external operational telemetry"):
        create_production_app(
            authenticator=issuer.provider(),
            rate_limiter=_DistributedLimiter(),
            security_audit=_DurableAudit(),
            secret_provider=_SecretProvider(),
            store=_ServerStore(tmp_path / "production.sqlite3"),
            dispatcher=_DistributedDispatcher(),
            security_settings=_production_settings(issuer),
            operational_settings=_operational_settings(tmp_path),
            scenario_ids=("shadow-demo",),
        )


def test_production_without_oidc_configuration_fails() -> None:
    with pytest.raises(ValueError, match="OIDC"):
        SecuritySettings(environment=RuntimeEnvironment.PRODUCTION)


def test_production_without_https_cors_fails() -> None:
    issuer = _Issuer()
    with pytest.raises(ValueError, match="CORS"):
        SecuritySettings(
            environment=RuntimeEnvironment.PRODUCTION,
            authentication_provider=AuthenticationProviderKind.OIDC,
            oidc=issuer.settings(),
            cors_allowed_origins=("http://localhost:5173",),
            hsts_enabled=True,
        )


def test_production_without_hsts_fails() -> None:
    issuer = _Issuer()
    with pytest.raises(ValueError, match="HSTS"):
        SecuritySettings(
            environment=RuntimeEnvironment.PRODUCTION,
            authentication_provider=AuthenticationProviderKind.OIDC,
            oidc=issuer.settings(),
            cors_allowed_origins=("https://command.example.com",),
        )


def test_valid_production_composition_is_created(tmp_path: Path) -> None:
    issuer = _Issuer()
    app = create_production_app(
        authenticator=issuer.provider(),
        rate_limiter=_DistributedLimiter(),
        security_audit=_DurableAudit(),
        secret_provider=_SecretProvider(),
        store=_ServerStore(tmp_path / "production.sqlite3"),
        dispatcher=_DistributedDispatcher(),
        telemetry=_ExternalTelemetry(),
        security_settings=_production_settings(issuer),
        operational_settings=_operational_settings(tmp_path),
        scenario_ids=("shadow-demo",),
    )
    assert isinstance(app, FastAPI)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200


def test_production_startup_rejects_invalid_approval_secret(tmp_path: Path) -> None:
    issuer = _Issuer()
    app = create_production_app(
        authenticator=issuer.provider(),
        rate_limiter=_DistributedLimiter(),
        security_audit=_DurableAudit(),
        secret_provider=_ShortSecretProvider(),
        store=_ServerStore(tmp_path / "production.sqlite3"),
        dispatcher=_DistributedDispatcher(),
        telemetry=_ExternalTelemetry(),
        security_settings=_production_settings(issuer),
        operational_settings=_operational_settings(tmp_path),
        scenario_ids=("shadow-demo",),
    )
    with pytest.raises(ConfigurationError, match="approval secret"), TestClient(app):
        pass


@pytest.mark.parametrize(
    "sensitive_value",
    [
        "Bearer opaque-access-token",
        "Cookie=session-cookie-value",
        "password=do-not-store",
        "secret=do-not-store",
    ],
    ids=("token", "cookie", "password", "secret"),
)
def test_security_audit_centrally_redacts_sensitive_values(sensitive_value: str) -> None:
    event = SecurityAuditEvent(
        event_type=SecurityEventType.AUTHENTICATION_FAILURE,
        subject=sensitive_value,
        request_id="request-1",
        result="failed",
    )
    serialized = event.model_dump_json()
    assert sensitive_value not in serialized
    assert "[REDACTED]" in serialized


async def test_rate_limit_returns_429_and_retry_after(tmp_path: Path) -> None:
    store = SqliteOperationalStore(tmp_path / "rate-limit.sqlite3")
    await store.initialize()
    app = create_app(
        SimulationService(store, ScenarioCatalog(("shadow-demo",))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_settings=SecuritySettings(simulation_creates_per_minute=1),
        rate_limiter=InMemoryRateLimiter(),
        security_audit=InMemorySecurityAuditSink(),
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer development:operator:rate-user"}
    assert client.post(
        "/api/v1/simulations", headers=headers, json={"scenario_id": "shadow-demo"}
    ).status_code == 202
    response = client.post(
        "/api/v1/simulations", headers=headers, json={"scenario_id": "shadow-demo"}
    )
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
