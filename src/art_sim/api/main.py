"""Development API entry point; production must supply a real identity adapter."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from hashlib import sha256
from pathlib import Path

from fastapi import FastAPI

from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationResultService,
    SimulationReviewService,
    SimulationService,
)
from art_sim.domain.exceptions import ConfigurationError
from art_sim.platform.checkpoint import sqlite_langgraph_checkpointer
from art_sim.platform.config import OperationalSettings, RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import InMemorySecurityAuditSink
from art_sim.security.config import SecuritySettings
from art_sim.security.rate_limit import InMemoryRateLimiter
from art_sim.worker.dispatcher import LocalSimulationDispatcher
from art_sim.worker.fixtures import shadow_scenario_catalog
from art_sim.worker.shadow import InMemoryScenarioRepository
from art_sim.worker.worker import SimulationWorker
from art_sim.worker.workflow import DurableSimulationWorkflow


def create_local_app() -> FastAPI:
    """Compose a local API that is intentionally unavailable under a production profile.

    The local catalog and process-scoped worker are controlled development adapters.
    Production must inject distributed activation, worker, scenario, and persistence
    adapters instead of reusing this composition root.
    """
    environment = RuntimeEnvironment(os.getenv("ART_ENV", RuntimeEnvironment.DEVELOPMENT.value))
    if environment is not RuntimeEnvironment.DEVELOPMENT:
        raise ConfigurationError("Non-development API requires an externally composed OIDC authenticator")
    settings = OperationalSettings(environment=environment)
    security_settings = SecuritySettings.from_environment(environment)
    database_path = Path(
        os.getenv("ART_SIM_OPERATIONAL_DB", str(settings.operational_database))
    )
    store = SqliteOperationalStore(database_path)
    dispatcher = LocalSimulationDispatcher(
        store,
        concurrency=int(os.getenv("ART_LOCAL_WORKER_CONCURRENCY", "10")),
    )
    configured_scenarios = shadow_scenario_catalog()
    catalog = ScenarioCatalog(tuple(item.scenario_id for item in configured_scenarios))
    scenarios = InMemoryScenarioRepository(configured_scenarios)

    async def store_ready() -> None:
        await store.list_runs(limit=1)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await store.initialize()
        async with sqlite_langgraph_checkpointer(database_path) as checkpointer:
            development_signing_material = sha256(
                f"development-only:{database_path.resolve()}".encode()
            ).digest()
            worker = SimulationWorker(
                store,
                catalog,
                scenarios,
                DurableSimulationWorkflow(checkpointer, development_signing_material),
                owner_id=f"local-{os.getpid()}",
            )
            await dispatcher.start(worker)
            try:
                yield
            finally:
                await dispatcher.stop()

    return create_app(
        SimulationService(
            store,
            catalog,
            settings.workflow_version,
            dispatcher,
        ),
        ApprovalService(store, dispatcher),
        HealthService({"operations_store": store_ready}),
        DevelopmentHeaderAuthenticator(enabled=True),
        lifespan,
        security_settings=security_settings,
        rate_limiter=InMemoryRateLimiter(),
        security_audit=InMemorySecurityAuditSink(),
        result_service=SimulationResultService(store),
        review_service=SimulationReviewService(store),
        cancellation_service=CancellationService(store, dispatcher),
    )


app = create_local_app()
