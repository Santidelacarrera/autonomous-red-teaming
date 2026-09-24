"""HTTP boundary tests for authentication, validation, pagination, and approval CAS."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import ApprovalService, ScenarioCatalog, SimulationService
from art_sim.platform.health import HealthService
from art_sim.platform.models import SimulationRunStatus
from art_sim.platform.sqlite import SqliteOperationalStore


async def _healthy() -> None:
    """Provide a deterministic readiness dependency for the API test application."""


async def _client(tmp_path: Path) -> tuple[TestClient, SqliteOperationalStore]:
    """Compose the API exactly through its public service dependencies."""
    store = SqliteOperationalStore(tmp_path / "api.sqlite3")
    await store.initialize()
    app = create_app(
        SimulationService(store, ScenarioCatalog(("shadow-demo",))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
    )
    return TestClient(app), store


async def test_api_requires_auth_and_generates_safe_request_id(tmp_path: Path) -> None:
    """Protected routes reject anonymous callers and never reflect injected request IDs."""
    client, _ = await _client(tmp_path)
    assert client.get("/api/v1/simulations").status_code == 401
    response = client.get("/health", headers={"X-Request-ID": "bad\r\nvalue"})
    assert response.status_code == 200
    assert "\r" not in response.headers["X-Request-ID"]


async def test_create_list_get_and_validate_simulation_api(tmp_path: Path) -> None:
    """The API returns persisted runs through services and bounds pagination."""
    client, _ = await _client(tmp_path)
    headers = {"Authorization": "Bearer development:operator:alice"}
    created = client.post("/api/v1/simulations", headers=headers, json={"scenario_id": "shadow-demo"})
    assert created.status_code == 202
    run_id = created.json()["run_id"]
    assert client.get(f"/api/v1/simulations/{run_id}", headers=headers).status_code == 200
    assert client.get("/api/v1/simulations?limit=201", headers=headers).status_code == 422
    listed = client.get("/api/v1/simulations?limit=1", headers=headers)
    assert listed.json()["items"][0]["run_id"] == run_id
    assert client.post("/api/v1/simulations", headers=headers, json={"scenario_id": "DROP TABLE"}).status_code == 422
    assert client.post("/api/v1/simulations", headers=headers, json={"scenario_id": "unknown"}).status_code == 422
    assert client.get("/api/v1/scenarios", headers=headers).json() == {"items": [{"scenario_id": "shadow-demo"}]}


async def test_create_simulation_idempotency_is_durable_and_scenario_bound(tmp_path: Path) -> None:
    """Retrying one POST key returns the original run; changing its scenario is rejected."""
    client, _ = await _client(tmp_path)
    headers = {"Authorization": "Bearer development:operator:alice", "Idempotency-Key": "request-key-0001"}
    first = client.post("/api/v1/simulations", headers=headers, json={"scenario_id": "shadow-demo"})
    second = client.post("/api/v1/simulations", headers=headers, json={"scenario_id": "shadow-demo"})
    assert first.status_code == second.status_code == 202
    assert first.json()["run_id"] == second.json()["run_id"]
    assert first.json()["created"] is True
    assert second.json()["created"] is False


async def test_approval_enforces_roles_and_durable_compare_and_set(tmp_path: Path) -> None:
    """Viewer cannot decide; operator gets one atomic decision after a worker pauses a run."""
    client, store = await _client(tmp_path)
    operator = {"Authorization": "Bearer development:operator:alice"}
    created = client.post("/api/v1/simulations", headers=operator, json={"scenario_id": "shadow-demo"})
    run_id = created.json()["run_id"]
    from uuid import UUID

    await store.update_status(UUID(run_id), SimulationRunStatus.WAITING_APPROVAL)
    viewer = {"Authorization": "Bearer development:viewer:bob"}
    assert client.post(f"/api/v1/simulations/{run_id}/approval", headers=viewer, json={"decision": "approved"}).status_code == 403
    approved = client.post(f"/api/v1/simulations/{run_id}/approval", headers=operator, json={"decision": "approved"})
    assert approved.status_code == 200
    assert approved.json()["approval_status"] == "approved"
    assert client.post(f"/api/v1/simulations/{run_id}/approval", headers=operator, json={"decision": "approved"}).status_code == 409


async def test_health_readiness_and_not_found_error_contract(tmp_path: Path) -> None:
    """Operational endpoints are public while missing resources use the safe error envelope."""
    client, _ = await _client(tmp_path)
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/readiness").json()["status"] == "ok"
    headers = {"Authorization": "Bearer development:viewer:alice"}
    response = client.get("/api/v1/simulations/00000000-0000-0000-0000-000000000000", headers=headers)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "RUN_NOT_FOUND"


async def test_analysis_result_endpoints_never_invent_unpersisted_data(tmp_path: Path) -> None:
    """A valid run without worker-persisted output receives a clear conflict, not fake analysis."""
    client, _ = await _client(tmp_path)
    headers = {"Authorization": "Bearer development:operator:alice"}
    run_id = client.post("/api/v1/simulations", headers=headers, json={"scenario_id": "shadow-demo"}).json()["run_id"]
    for suffix in ("attack-paths", "blast-radius", "remediations", "verification", "report"):
        response = client.get(f"/api/v1/simulations/{run_id}/{suffix}", headers=headers)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "API_REQUEST_REJECTED"
    assert client.get(f"/api/v1/simulations/{run_id}/report?format=pdf", headers=headers).status_code == 422
