"""API-to-worker E2E coverage using only controlled in-memory Shadow topology."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from art_sim.api.app import create_app
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationResultService,
    SimulationService,
)
from art_sim.platform.checkpoint import sqlite_langgraph_checkpointer
from art_sim.platform.health import HealthService
from art_sim.platform.models import SimulationRunStatus
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import InMemorySecurityAuditSink
from art_sim.security.providers.development import DevelopmentHeaderAuthenticator
from art_sim.security.rate_limit import InMemoryRateLimiter
from art_sim.worker.fixtures import shadow_demo_scenario
from art_sim.worker.jobs import CancellationReceipt, DispatchReceipt
from art_sim.worker.models import SimulationScenario
from art_sim.worker.ports import DispatcherScope
from art_sim.worker.shadow import InMemoryScenarioRepository
from art_sim.worker.worker import SimulationWorker, WorkerRunResult
from art_sim.worker.workflow import DurableSimulationWorkflow


class _ManualDispatcher:
    """Test activation adapter; explicit worker calls keep HTTP and work separated."""

    deployment_scope: ClassVar[DispatcherScope] = DispatcherScope.PROCESS

    def __init__(self) -> None:
        self.submitted: list[UUID] = []

    async def dispatch(self, run_id: UUID) -> DispatchReceipt:
        self.submitted.append(run_id)
        return DispatchReceipt(run_id=run_id, message_id=uuid4(), accepted=True)

    async def cancel(self, run_id: UUID) -> CancellationReceipt:
        return CancellationReceipt(run_id=run_id, accepted=True)


async def _healthy() -> None:
    """Deterministic readiness probe."""


async def _client(
    database: Path,
    scenario: SimulationScenario,
) -> tuple[TestClient, SqliteOperationalStore, _ManualDispatcher, InMemorySecurityAuditSink]:
    store = SqliteOperationalStore(database)
    await store.initialize()
    dispatcher = _ManualDispatcher()
    audit = InMemorySecurityAuditSink()
    catalog = ScenarioCatalog((scenario.scenario_id,))
    app = create_app(
        SimulationService(store, catalog, "worker-v1", dispatcher),
        ApprovalService(store, dispatcher),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_settings=None,
        rate_limiter=InMemoryRateLimiter(),
        security_audit=audit,
        result_service=SimulationResultService(store),
        cancellation_service=CancellationService(store, dispatcher),
    )
    return TestClient(app), store, dispatcher, audit


def _headers(role: str = "operator") -> dict[str, str]:
    return {"Authorization": f"Bearer development:{role}:api-user"}


async def _worker(
    database: Path,
    store: SqliteOperationalStore,
    scenario: SimulationScenario,
    owner: str,
) -> tuple[WorkerRunResult, UUID]:
    run_id = (await store.list_runs(limit=1))[0].run_id
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = SimulationWorker(
            store,
            ScenarioCatalog((scenario.scenario_id,)),
            InMemoryScenarioRepository((scenario,)),
            DurableSimulationWorkflow(saver, b"integration-signing-material-32-bytes"),
            owner_id=owner,
        )
        return await worker.run(run_id), run_id


async def test_api_worker_shadow_e2e_persists_and_serves_every_result(tmp_path: Path) -> None:
    database = tmp_path / "api-worker.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    client, store, dispatcher, _ = await _client(database, scenario)
    created = client.post(
        "/api/v1/simulations",
        headers=_headers(),
        json={"scenario_id": scenario.scenario_id},
    )
    assert created.status_code == 202
    run_id = UUID(created.json()["run_id"])
    assert dispatcher.submitted == [run_id]
    assert await _worker(database, store, scenario, "e2e") == (
        WorkerRunResult.SUCCEEDED,
        run_id,
    )

    for suffix in (
        "risk",
        "attack-paths",
        "blast-radius",
        "remediations",
        "verification",
        "report",
    ):
        response = client.get(f"/api/v1/simulations/{run_id}/{suffix}", headers=_headers())
        assert response.status_code == 200, response.text
    report = client.get(
        f"/api/v1/simulations/{run_id}/report",
        headers=_headers(),
    ).json()
    assert "# Security Simulation Report" in report["content"]


async def test_result_endpoints_return_409_during_created_running_and_waiting(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pending-results.sqlite3"
    scenario = shadow_demo_scenario()
    client, store, _, _ = await _client(database, scenario)
    created = client.post(
        "/api/v1/simulations",
        headers=_headers(),
        json={"scenario_id": scenario.scenario_id},
    )
    run_id = UUID(created.json()["run_id"])
    assert client.get(f"/api/v1/simulations/{run_id}/risk", headers=_headers()).status_code == 409

    claim = await store.acquire_execution(run_id, "probe", UUID(int=1), lease_seconds=1)
    assert claim is not None
    assert client.get(f"/api/v1/simulations/{run_id}/risk", headers=_headers()).status_code == 409
    await store.mark_waiting_approval(run_id, "probe", claim.fencing_token)
    assert client.get(f"/api/v1/simulations/{run_id}/risk", headers=_headers()).status_code == 409


async def test_api_hitl_approval_restart_resume_hmac_cas_and_audit(tmp_path: Path) -> None:
    database = tmp_path / "api-hitl.sqlite3"
    scenario = shadow_demo_scenario()
    client, store, dispatcher, security_audit = await _client(database, scenario)
    created = client.post(
        "/api/v1/simulations",
        headers=_headers(),
        json={"scenario_id": scenario.scenario_id},
    )
    run_id = UUID(created.json()["run_id"])
    first, _ = await _worker(database, store, scenario, "before-restart")
    assert first is WorkerRunResult.WAITING_APPROVAL

    approved = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers=_headers(),
        json={"decision": "approved"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "resuming"
    assert dispatcher.submitted[-1] == run_id
    replay = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers=_headers(),
        json={"decision": "approved"},
    )
    assert replay.status_code == 409

    resumed, _ = await _worker(database, store, scenario, "after-restart")
    assert resumed is WorkerRunResult.SUCCEEDED
    assert (await store.get_result(run_id)).approval is not None
    operational_events = {event.event_type for event in await store.list_events(run_id)}
    assert {
        "simulation.approved",
        "simulation.resumed",
        "simulation.completed",
    } <= operational_events
    assert any(event.run_id == run_id for event in await security_audit.recent())


async def test_api_hitl_rejection_after_restart_is_terminal(tmp_path: Path) -> None:
    database = tmp_path / "api-reject.sqlite3"
    scenario = shadow_demo_scenario()
    client, store, _, _ = await _client(database, scenario)
    created = client.post(
        "/api/v1/simulations",
        headers=_headers(),
        json={"scenario_id": scenario.scenario_id},
    )
    run_id = UUID(created.json()["run_id"])
    await _worker(database, store, scenario, "before-reject")
    rejected = client.post(
        f"/api/v1/simulations/{run_id}/approval",
        headers=_headers(),
        json={"decision": "rejected"},
    )
    assert rejected.status_code == 200
    final, _ = await _worker(database, store, scenario, "after-reject")
    assert final is WorkerRunResult.REJECTED
    response = client.get(f"/api/v1/simulations/{run_id}/risk", headers=_headers())
    assert response.status_code == 409
    run = client.get(f"/api/v1/simulations/{run_id}", headers=_headers()).json()
    assert run["status"] == SimulationRunStatus.REJECTED.value
    assert "traceback" not in response.text.lower()


async def test_api_cancel_is_authorized_idempotent_and_has_no_results(tmp_path: Path) -> None:
    database = tmp_path / "api-cancel.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    client, store, _, _ = await _client(database, scenario)
    created = client.post(
        "/api/v1/simulations",
        headers=_headers(),
        json={"scenario_id": scenario.scenario_id},
    )
    run_id = UUID(created.json()["run_id"])
    assert client.post(
        f"/api/v1/simulations/{run_id}/cancel",
        headers=_headers("viewer"),
    ).status_code == 403
    first = client.post(
        f"/api/v1/simulations/{run_id}/cancel",
        headers=_headers(),
    )
    repeated = client.post(
        f"/api/v1/simulations/{run_id}/cancel",
        headers=_headers(),
    )
    assert first.status_code == repeated.status_code == 200
    assert first.json()["status"] == repeated.json()["status"] == "cancelled"
    assert client.get(
        f"/api/v1/simulations/{run_id}/risk",
        headers=_headers(),
    ).status_code == 409
    assert (await store.get_run(run_id)).status is SimulationRunStatus.CANCELLED


async def test_operational_event_timeline_requires_audit_permission(tmp_path: Path) -> None:
    database = tmp_path / "api-events.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    client, _, _, _ = await _client(database, scenario)
    run_id = client.post(
        "/api/v1/simulations",
        headers=_headers(),
        json={"scenario_id": scenario.scenario_id},
    ).json()["run_id"]
    assert client.get(
        f"/api/v1/simulations/{run_id}/events",
        headers=_headers("operator"),
    ).status_code == 403
    timeline = client.get(
        f"/api/v1/simulations/{run_id}/events",
        headers=_headers("admin"),
    )
    assert timeline.status_code == 200
    assert timeline.json()["items"][0]["event_type"] == "simulation.created"
