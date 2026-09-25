"""Fail-closed production API composition using only injected deployment adapters."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI

from art_sim.api.app import create_app
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationResultService,
    SimulationReviewService,
    SimulationService,
)
from art_sim.domain.exceptions import ConfigurationError
from art_sim.observability.sink import (
    ExternalOperationalTelemetrySink,
    TelemetryCapability,
)
from art_sim.platform.config import OperationalSettings, RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.platform.ports import OperationalStoreCapability, ServerOperationalStore
from art_sim.platform.production_config import ProductionDependencySettings
from art_sim.security.audit import (
    AuditDurability,
    DurableSecurityAuditSink,
    SecurityAuditEvent,
    SecurityEventType,
)
from art_sim.security.config import AuthenticationProviderKind, SecuritySettings
from art_sim.security.identity import IdentityProvider, IdentityProviderCapability
from art_sim.security.providers.oidc import OidcSettings
from art_sim.security.rate_limit import DistributedRateLimiter, RateLimiterScope
from art_sim.security.secrets import (
    ExternalSecretProvider,
    SecretProviderCapability,
)
from art_sim.worker.ports import DispatcherScope, DistributedSimulationDispatcher


def create_production_app(
    *,
    authenticator: IdentityProvider | None,
    rate_limiter: DistributedRateLimiter | None,
    security_audit: DurableSecurityAuditSink | None,
    secret_provider: ExternalSecretProvider | None,
    store: ServerOperationalStore | None,
    dispatcher: DistributedSimulationDispatcher | None,
    telemetry: ExternalOperationalTelemetrySink | None = None,
    security_settings: SecuritySettings,
    operational_settings: OperationalSettings,
    dependency_settings: ProductionDependencySettings | None = None,
    scenario_ids: tuple[str, ...],
) -> FastAPI:
    """Compose production from explicit real adapters and validate them before serving.

    This root does not construct Redis, SIEM, cloud secret-manager, OIDC, or persistence
    clients. Deployments own those adapters and their lifecycle.

    Raises:
        ConfigurationError: If the profile or any mandatory dependency is unsuitable.
    """
    if security_settings.environment is not RuntimeEnvironment.PRODUCTION:
        raise ConfigurationError("Production composition requires the production profile")
    if operational_settings.environment is not RuntimeEnvironment.PRODUCTION:
        raise ConfigurationError("Operational settings must use the production profile")
    if dependency_settings is None:
        raise ConfigurationError("Production dependency configuration is required")
    if (
        dependency_settings.secrets.approval_hmac_secret_name
        != operational_settings.approval_secret_name
    ):
        raise ConfigurationError("Approval secret reference does not match production settings")
    if security_settings.authentication_provider is not AuthenticationProviderKind.OIDC:
        raise ConfigurationError("Production composition requires OIDC authentication")
    if (
        authenticator is None
        or getattr(authenticator, "deployment_capability", None)
        is not IdentityProviderCapability.OIDC_VERIFIED
    ):
        raise ConfigurationError("Production requires an OIDC authenticator")
    authenticator_settings = getattr(authenticator, "settings", None)
    if not isinstance(authenticator_settings, OidcSettings):
        raise ConfigurationError("Production OIDC authenticator has no validated settings")
    if authenticator_settings != security_settings.oidc:
        raise ConfigurationError("OIDC authenticator does not match production security settings")
    if (
        rate_limiter is None
        or getattr(rate_limiter, "deployment_scope", None) is not RateLimiterScope.DISTRIBUTED
    ):
        raise ConfigurationError("Production requires a shared rate limiter")
    if (
        security_audit is None
        or getattr(security_audit, "durability", None) is not AuditDurability.DURABLE
    ):
        raise ConfigurationError("Production requires a durable security audit sink")
    if (
        secret_provider is None
        or getattr(secret_provider, "deployment_capability", None)
        is not SecretProviderCapability.EXTERNAL
    ):
        raise ConfigurationError("Production requires an external secret provider")
    if (
        store is None
        or getattr(store, "deployment_capability", None)
        is not OperationalStoreCapability.SERVER_GRADE
    ):
        raise ConfigurationError("Production requires a server-grade operational store")
    if (
        dispatcher is None
        or getattr(dispatcher, "deployment_scope", None) is not DispatcherScope.DISTRIBUTED
    ):
        raise ConfigurationError("Production requires a distributed simulation dispatcher")
    if (
        telemetry is None
        or getattr(telemetry, "deployment_capability", None)
        is not TelemetryCapability.EXTERNAL
    ):
        raise ConfigurationError("Production requires external operational telemetry")

    async def secret_ready() -> None:
        await secret_provider.health_check()
        value = await operational_settings.approval_secret_async(secret_provider)
        del value

    readiness = HealthService(
        {
            "database": store.health_check,
            "broker": dispatcher.health_check,
            "secret_provider": secret_ready,
            "identity_provider": authenticator.health_check,
            "rate_limiter": rate_limiter.health_check,
            "audit": security_audit.health_check,
            "telemetry": telemetry.health_check,
        }
    )

    async def audit_startup_failure() -> None:
        """Attempt safe evidence without replacing the original startup failure."""
        try:
            await security_audit.append(
                SecurityAuditEvent(
                    event_type=SecurityEventType.SECURITY_CONFIGURATION_FAILURE,
                    request_id=f"startup-{uuid4()}",
                    source="startup",
                    result="failed",
                )
            )
        except Exception:  # noqa: BLE001 - unavailable audit cannot allow startup
            return

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            approval_secret = await operational_settings.approval_secret_async(secret_provider)
            del approval_secret
            await store.initialize()
        except Exception:
            await audit_startup_failure()
            raise
        try:
            yield
        finally:
            await asyncio.gather(
                dispatcher.close(),
                telemetry.close(),
                security_audit.close(),
                rate_limiter.close(),
                authenticator.close(),
                secret_provider.close(),
                store.close(),
                return_exceptions=True,
            )

    return create_app(
        SimulationService(
            store,
            ScenarioCatalog(scenario_ids),
            operational_settings.workflow_version,
            dispatcher,
        ),
        ApprovalService(store, dispatcher),
        readiness,
        authenticator,
        lifespan,
        security_settings=security_settings,
        rate_limiter=rate_limiter,
        security_audit=security_audit,
        result_service=SimulationResultService(store),
        review_service=SimulationReviewService(store),
        cancellation_service=CancellationService(store, dispatcher),
    )
