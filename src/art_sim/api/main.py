"""Development API entry point; production must supply a real identity adapter."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import ApprovalService, ScenarioCatalog, SimulationService
from art_sim.domain.exceptions import ConfigurationError
from art_sim.platform.config import OperationalSettings, RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import InMemorySecurityAuditSink
from art_sim.security.config import SecuritySettings
from art_sim.security.rate_limit import InMemoryRateLimiter


def create_local_app() -> FastAPI:
    """Compose a local API that is intentionally unavailable under a production profile.

    The local catalog is a controlled API demonstration only; a worker integration must
    register production scenarios and persist workflow outputs before result endpoints
    can expose them.
    """
    environment = RuntimeEnvironment(os.getenv("ART_ENV", RuntimeEnvironment.DEVELOPMENT.value))
    if environment is not RuntimeEnvironment.DEVELOPMENT:
        raise ConfigurationError("Non-development API requires an externally composed OIDC authenticator")
    settings = OperationalSettings(environment=environment)
    security_settings = SecuritySettings.from_environment(environment)
    store = SqliteOperationalStore(Path(os.getenv("ART_SIM_OPERATIONAL_DB", str(settings.operational_database))))

    async def store_ready() -> None:
        await store.list_runs(limit=1)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await store.initialize()
        yield

    return create_app(
        SimulationService(store, ScenarioCatalog(("shadow-demo",)), settings.workflow_version),
        ApprovalService(store),
        HealthService({"operations_store": store_ready}),
        DevelopmentHeaderAuthenticator(enabled=True),
        lifespan,
        security_settings=security_settings,
        rate_limiter=InMemoryRateLimiter(),
        security_audit=InMemorySecurityAuditSink(),
    )


app = create_local_app()
