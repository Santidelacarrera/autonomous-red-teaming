"""Integration tests for the PostgreSQL operational store against a real PostgreSQL.

Requires a reachable PostgreSQL (set ART_PG_TEST_DSN, or run the default dev container at
postgresql://postgres:devpw@127.0.0.1:55432/artsim). Skipped if no database is reachable.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import asyncpg
import pytest

from art_sim.adapters.postgres_store import PostgresOperationalStore
from art_sim.domain.exceptions import ApprovalRequiredError
from art_sim.platform.models import SimulationRun, SimulationRunStatus
from art_sim.platform.ports import OperationalStoreCapability
from art_sim.platform.sqlite import OperationalStoreError
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus

DSN = os.getenv("ART_PG_TEST_DSN", "postgresql://postgres:devpw@127.0.0.1:55432/artsim")


class _Clock:
    """Controllable timezone-aware clock for deterministic lease-expiry tests."""

    def __init__(self) -> None:
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


async def _reachable() -> bool:
    try:
        conn = await asyncpg.connect(DSN, timeout=3)
    except (OSError, asyncpg.PostgresError):
        return False
    await conn.close()
    return True


@pytest.fixture
async def store() -> AsyncGenerator[tuple[PostgresOperationalStore, _Clock]]:
    if not await _reachable():
        pytest.skip("No PostgreSQL reachable for integration tests")
    pool = await asyncpg.create_pool(DSN, min_size=1, max_size=8)
    clock = _Clock()
    adapter = PostgresOperationalStore(pool, clock=clock)
    await adapter.initialize()
    async with pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE simulation_reviews, simulation_results, audit_events, api_idempotency, "
            "workflow_checkpoints, worker_leases, simulation_runs RESTART IDENTITY CASCADE"
        )
    yield adapter, clock
    await adapter.close()


def _run(status: SimulationRunStatus = SimulationRunStatus.CREATED) -> SimulationRun:
    return SimulationRun(
        scenario_id="shadow-demo",
        graph_version="g-v1",
        workflow_version="v1",
        created_by="pg-test",
        status=status,
    )


async def test_declares_server_grade_capability() -> None:
    assert PostgresOperationalStore.deployment_capability is OperationalStoreCapability.SERVER_GRADE


async def test_create_get_and_duplicate(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, _ = store
    run = _run()
    await adapter.create_run(run)
    fetched = await adapter.get_run(run.run_id)
    assert fetched.run_id == run.run_id
    with pytest.raises(OperationalStoreError):
        await adapter.create_run(run)
    events = await adapter.list_events(run.run_id)
    assert events[0].event_type == "simulation.created"


async def test_idempotent_creation(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, _ = store
    run = _run()
    created, first = await adapter.create_run_idempotent(run, "idem-key-0001")
    assert first is True
    again, second = await adapter.create_run_idempotent(_run(), "idem-key-0001")
    assert second is False
    assert again.run_id == created.run_id


async def test_single_owner_and_fencing(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, clock = store
    run = _run()
    await adapter.create_run(run)
    claim = await adapter.acquire_execution(run.run_id, "worker-A", uuid4(), lease_seconds=300)
    assert claim is not None and claim.fencing_token == 1
    # A second worker cannot acquire while the lease is live.
    assert await adapter.acquire_execution(run.run_id, "worker-B", uuid4(), lease_seconds=300) is None
    # After the lease expires, another worker takes over with an incremented fencing token.
    clock.advance(301)
    takeover = await adapter.acquire_execution(run.run_id, "worker-B", uuid4(), lease_seconds=300)
    assert takeover is not None and takeover.fencing_token == 2 and takeover.attempt == 2


async def test_renew_requires_exact_owner_and_token(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, _ = store
    run = _run()
    await adapter.create_run(run)
    claim = await adapter.acquire_execution(run.run_id, "w", uuid4())
    assert claim is not None
    assert await adapter.renew_execution(run.run_id, "w", claim.fencing_token) is True
    assert await adapter.renew_execution(run.run_id, "w", claim.fencing_token + 1) is False
    assert await adapter.renew_execution(run.run_id, "other", claim.fencing_token) is False


async def test_approval_cas_only_from_waiting(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, _ = store
    run = _run(SimulationRunStatus.WAITING_APPROVAL)
    await adapter.create_run(run)
    decided = await adapter.decide(run.run_id, ApprovalDecision.APPROVED, "approver", "approved for integration test")
    assert decided.approval_status is ApprovalStatus.APPROVED
    assert decided.status is SimulationRunStatus.RESUMING
    # A second decision is rejected (no longer pending/waiting).
    with pytest.raises(ApprovalRequiredError):
        await adapter.decide(run.run_id, ApprovalDecision.APPROVED, "approver", "second decision attempt")


async def test_stale_worker_cannot_complete(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, clock = store
    run = _run()
    await adapter.create_run(run)
    first = await adapter.acquire_execution(run.run_id, "w1", uuid4(), lease_seconds=300)
    assert first is not None
    clock.advance(301)
    second = await adapter.acquire_execution(run.run_id, "w2", uuid4(), lease_seconds=300)
    assert second is not None
    # The stale worker's fencing token is no longer valid for an owned operation.
    with pytest.raises(OperationalStoreError):
        await adapter.release_execution(run.run_id, "w1", first.fencing_token)


async def test_request_and_finalize_cancellation(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, _ = store
    run = _run()
    await adapter.create_run(run)
    claim = await adapter.acquire_execution(run.run_id, "w", uuid4())
    assert claim is not None
    requested = await adapter.request_cancellation(run.run_id, "operator")
    assert requested.cancellation_requested is True
    cancelled = await adapter.cancel_execution(run.run_id, "w", claim.fencing_token)
    assert cancelled.status is SimulationRunStatus.CANCELLED


async def test_health_check(store: tuple[PostgresOperationalStore, _Clock]) -> None:
    adapter, _ = store
    await adapter.health_check()
