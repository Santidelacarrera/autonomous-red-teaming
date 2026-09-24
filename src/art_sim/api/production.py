"""Fail-closed production API composition using only injected deployment adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from art_sim.api.app import create_app
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationResultService,
    SimulationService,
)
from art_sim.domain.exceptions import ConfigurationError
from art_sim.observability.sink import OperationalTelemetrySink, TelemetryCapability
from art_sim.platform.config import OperationalSettings, RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.platform.ports import OperationalStore, OperationalStoreCapability
from art_sim.security.audit import AuditDurability, DurableSecurityAuditSink
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
    store: OperationalStore | None,
    dispatcher: DistributedSimulationDispatcher | None,
    telemetry: OperationalTelemetrySink | None = None,
    security_settings: SecuritySettings,
    operational_settings: OperationalSettings,
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

    async def store_ready() -> None:
        await store.list_runs(limit=1)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        approval_secret = await operational_settings.approval_secret_async(secret_provider)
        del approval_secret
        await store.initialize()
        yield

    return create_app(
        SimulationService(
            store,
            ScenarioCatalog(scenario_ids),
            operational_settings.workflow_version,
            dispatcher,
        ),
        ApprovalService(store, dispatcher),
        HealthService({"operations_store": store_ready}),
        authenticator,
        lifespan,
        security_settings=security_settings,
        rate_limiter=rate_limiter,
        security_audit=security_audit,
        result_service=SimulationResultService(store),
        cancellation_service=CancellationService(store, dispatcher),
    )
