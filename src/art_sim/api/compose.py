"""Production composition root: wire the real adapters from the environment.

Builds every concrete production adapter (OIDC, PostgreSQL store, Redis Streams broker,
Redis rate limiter, OTLP telemetry, durable audit, mounted secrets) from environment
configuration and hands them to ``create_production_app``, which enforces the fail-closed
capability contract. Importing or calling this requires the ``redis``, ``postgres`` and
``telemetry`` extras.

This is the entrypoint the container runs in production (via ``art_sim.api.serve``); the
development ``art_sim.api.main`` composition is never used outside development.
"""

from __future__ import annotations

import os
from pathlib import Path

import asyncpg
from fastapi import FastAPI

from art_sim.adapters.jsonl_audit_sink import JsonlDurableSecurityAuditSink
from art_sim.adapters.mounted_secret_provider import MountedSecretsProvider
from art_sim.adapters.otlp_telemetry import OtlpTelemetrySink
from art_sim.adapters.postgres_store import PostgresOperationalStore
from art_sim.adapters.redis_rate_limiter import RedisRateLimiter
from art_sim.adapters.redis_streams_broker import RedisStreamsBrokerTransport, RedisStreamsSettings
from art_sim.api.production import create_production_app
from art_sim.domain.exceptions import ConfigurationError
from art_sim.platform.config import (
    OperationalSettings,
    RuntimeEnvironment,
    approval_ttl_from_environment,
)
from art_sim.platform.production_config import ProductionDependencySettings
from art_sim.security.config import SecuritySettings
from art_sim.security.providers.oidc import OidcIdentityProvider
from art_sim.worker.dispatcher import BrokerSimulationDispatcher
from art_sim.worker.fixtures import shadow_scenario_catalog

# A production review window is always bounded; 24 h unless the operator sets another value.
DEFAULT_PRODUCTION_APPROVAL_TTL_SECONDS = 86_400


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ConfigurationError(f"Required environment variable {name!r} is not set")
    return value


async def build_production_app() -> FastAPI:
    """Compose the fail-closed production API from real, environment-configured adapters."""
    security_settings = SecuritySettings.from_environment(RuntimeEnvironment.PRODUCTION)
    if security_settings.oidc is None:  # pragma: no cover - from_environment already enforces this
        raise ConfigurationError("Production composition requires OIDC configuration")
    dependency_settings = ProductionDependencySettings.from_environment()
    operational_settings = OperationalSettings(
        environment=RuntimeEnvironment.PRODUCTION,
        approval_secret_name=dependency_settings.secrets.approval_hmac_secret_name,
    )

    secret_provider = MountedSecretsProvider(Path(_required_env("ART_SECRETS_DIR")))
    database_dsn = (
        await secret_provider.get_secret(dependency_settings.secrets.database_secret_name)
    ).get_secret_value()
    broker_url = (
        await secret_provider.get_secret(dependency_settings.secrets.broker_secret_name)
    ).get_secret_value()

    pool = await asyncpg.create_pool(
        database_dsn,
        min_size=dependency_settings.database.pool_min_size,
        max_size=dependency_settings.database.pool_max_size,
    )
    if pool is None:  # pragma: no cover - defensive
        raise ConfigurationError("Unable to create a PostgreSQL connection pool")
    store = PostgresOperationalStore(
        pool, approval_ttl=approval_ttl_from_environment(DEFAULT_PRODUCTION_APPROVAL_TTL_SECONDS)
    )

    transport = RedisStreamsBrokerTransport.from_url(
        broker_url,
        RedisStreamsSettings(
            visibility_timeout_seconds=dependency_settings.broker.visibility_timeout_seconds
        ),
    )
    dispatcher = BrokerSimulationDispatcher(store, transport)
    rate_limiter = RedisRateLimiter.from_url(_required_env("ART_RATE_LIMIT_ENDPOINT"))
    telemetry = OtlpTelemetrySink.from_endpoint(_required_env("ART_OTLP_ENDPOINT"))
    audit = JsonlDurableSecurityAuditSink(
        Path(os.getenv("ART_AUDIT_PATH", "/app/var/audit/security.jsonl")),
        dependency_settings.audit_retention,
    )
    authenticator = OidcIdentityProvider(security_settings.oidc)
    scenario_ids = tuple(scenario.scenario_id for scenario in shadow_scenario_catalog())

    return create_production_app(
        authenticator=authenticator,
        rate_limiter=rate_limiter,
        security_audit=audit,
        secret_provider=secret_provider,
        store=store,
        dispatcher=dispatcher,
        telemetry=telemetry,
        security_settings=security_settings,
        operational_settings=operational_settings,
        dependency_settings=dependency_settings,
        scenario_ids=scenario_ids,
    )
