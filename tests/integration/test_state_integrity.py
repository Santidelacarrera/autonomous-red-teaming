"""Invalid lifecycle transitions never modify the persisted simulation.

For *every* (source, target) pair the state machine forbids — and for every store operation
attempted from a state that does not allow it — the durable record must be byte-for-byte
unchanged afterwards: run row, audit trail, lease, checkpoint and result tables. The same
suite runs against the SQLite development store and, when ``ART_PG_TEST_DSN`` is reachable,
the PostgreSQL production store, so both adapters are held to one behavioral contract.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import pytest

from art_sim.adapters.postgres_store import PostgresOperationalStore
from art_sim.domain.exceptions import ApprovalRequiredError, GraphEngineError
from art_sim.platform.lifecycle import SimulationRunStateMachine
from art_sim.platform.models import SimulationRun, SimulationRunStatus, WorkflowCheckpoint
from art_sim.platform.sqlite import OperationalStoreError, SqliteOperationalStore
from art_sim.remediation.models import ApprovalDecision

DSN = os.getenv("ART_PG_TEST_DSN", "postgresql://postgres:devpw@127.0.0.1:55432/artsim")
TABLES = (
    "simulation_runs",
    "audit_events",
    "worker_leases",
    "workflow_checkpoints",
    "simulation_results",
    "simulation_reviews",
    "api_idempotency",
)
ALL = tuple(SimulationRunStatus)


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Backend:
    """A store plus the ability to read every table raw, to prove nothing moved."""

    def __init__(self, name: str, store: Any, clock: _Clock, reader: Any) -> None:
        self.name, self.store, self.clock, self._reader = name, store, clock, reader

    async def snapshot(self) -> dict[str, list[tuple[str, ...]]]:
        snapshot: dict[str, list[tuple[str, ...]]] = await self._reader()
        return snapshot


async def _pg_reachable() -> bool:
    try:
        connection = await asyncpg.connect(DSN, timeout=3)
    except (OSError, asyncpg.PostgresError):
        return False
    await connection.close()
    return True


@pytest.fixture(params=["sqlite", "postgres"])
async def backend(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncGenerator[Backend]:
    clock = _Clock()
    if request.param == "sqlite":
        database = tmp_path / "integrity.sqlite3"
        store = SqliteOperationalStore(database, clock=clock)
        await store.initialize()

        async def read_sqlite() -> dict[str, list[tuple[str, ...]]]:
            connection = sqlite3.connect(database)
            try:
                return {
                    table: sorted(
                        tuple(str(value) for value in row)
                        for row in connection.execute(f"SELECT * FROM {table}")
                    )
                    for table in TABLES
                }
            finally:
                connection.close()

        yield Backend("sqlite", store, clock, read_sqlite)
        return

    if not await _pg_reachable():
        pytest.skip("No PostgreSQL reachable for integration tests")
    pool = await asyncpg.create_pool(DSN, min_size=1, max_size=4)
    pg_store = PostgresOperationalStore(pool, clock=clock)
    await pg_store.initialize()
    async with pool.acquire() as connection:
        await connection.execute(
            "TRUNCATE simulation_reviews, simulation_results, audit_events, api_idempotency, "
            "workflow_checkpoints, worker_leases, simulation_runs RESTART IDENTITY CASCADE"
        )

    async def read_postgres() -> dict[str, list[tuple[str, ...]]]:
        async with pool.acquire() as connection:
            return {
                table: sorted(
                    tuple(str(value) for value in row.values())
                    for row in await connection.fetch(f"SELECT * FROM {table}")
                )
                for table in TABLES
            }

    yield Backend("postgres", pg_store, clock, read_postgres)
    await pg_store.close()


def _run(status: SimulationRunStatus = SimulationRunStatus.CREATED) -> SimulationRun:
    return SimulationRun(
        scenario_id="shadow-demo",
        graph_version="g-v1",
        workflow_version="v1",
        created_by="integrity-test",
        status=status,
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


async def _persisted(backend: Backend, status: SimulationRunStatus) -> SimulationRun:
    run = _run(status)
    await backend.store.create_run(run)
    return run


FORBIDDEN = [
    (source, target)
    for source in ALL
    for target in ALL
    if target not in SimulationRunStateMachine._ALLOWED[source]
]
ALLOWED = [
    (source, target)
    for source in ALL
    for target in SimulationRunStateMachine._ALLOWED[source]
]


# --------------------------------------------------------- every forbidden transition


@pytest.mark.parametrize("source", ALL)
async def test_every_forbidden_transition_leaves_all_tables_unchanged(
    backend: Backend, source: SimulationRunStatus
) -> None:
    run = await _persisted(backend, source)
    before = await backend.snapshot()
    targets = [t for s, t in FORBIDDEN if s is source]
    assert targets, "every status has at least one forbidden target"

    for target in targets:
        with pytest.raises(GraphEngineError):
            await backend.store.update_status(run.run_id, target)
        assert await backend.snapshot() == before, f"{source} -> {target} mutated state"
    assert (await backend.store.get_run(run.run_id)).status is source


@pytest.mark.parametrize(
    ("source", "target"),
    [pair for pair in ALLOWED if pair[0] not in SimulationRunStateMachine.TERMINAL],
)
async def test_every_allowed_transition_is_applied_exactly(
    backend: Backend, source: SimulationRunStatus, target: SimulationRunStatus
) -> None:
    """Positive control: the guard rejects what is forbidden, not everything."""
    run = await _persisted(backend, source)
    backend.clock.advance(5)
    moved = await backend.store.update_status(run.run_id, target)
    assert moved.status is target
    assert (await backend.store.get_run(run.run_id)).status is target


def test_matrix_sanity_terminal_states_have_no_exits() -> None:
    for status in SimulationRunStateMachine.TERMINAL:
        assert SimulationRunStateMachine._ALLOWED[status] == frozenset()
    assert len(FORBIDDEN) + len(ALLOWED) == len(ALL) ** 2


# ------------------------------------------- store operations from the wrong state


@pytest.mark.parametrize(
    "status",
    [s for s in ALL if s is not SimulationRunStatus.WAITING_APPROVAL],
)
async def test_decision_is_refused_unless_the_run_is_waiting(
    backend: Backend, status: SimulationRunStatus
) -> None:
    run = await _persisted(backend, status)
    before = await backend.snapshot()
    for decision in ApprovalDecision:
        with pytest.raises(ApprovalRequiredError):
            await backend.store.decide(run.run_id, decision, "alice", "Reviewed in detail here.")
    assert await backend.snapshot() == before


async def test_second_decision_cannot_replace_the_first(backend: Backend) -> None:
    run = await _persisted(backend, SimulationRunStatus.WAITING_APPROVAL)
    await backend.store.decide(run.run_id, ApprovalDecision.APPROVED, "alice", "First reviewer approves.")
    before = await backend.snapshot()
    with pytest.raises(ApprovalRequiredError):
        await backend.store.decide(run.run_id, ApprovalDecision.REJECTED, "bob", "Second reviewer objects.")
    assert await backend.snapshot() == before
    final = await backend.store.get_run(run.run_id)
    assert (final.approval_actor, final.approval_status.value) == ("alice", "approved")


async def test_invalid_decision_input_does_not_write(backend: Backend) -> None:
    run = await _persisted(backend, SimulationRunStatus.WAITING_APPROVAL)
    before = await backend.snapshot()
    with pytest.raises(ApprovalRequiredError):
        await backend.store.decide(run.run_id, ApprovalDecision.APPROVED, "  ", "Reviewed in detail here.")
    with pytest.raises(ApprovalRequiredError):
        await backend.store.decide(run.run_id, ApprovalDecision.APPROVED, "alice", "too short")
    assert await backend.snapshot() == before


@pytest.mark.parametrize(
    "status",
    [
        SimulationRunStatus.WAITING_APPROVAL,
        SimulationRunStatus.SUCCEEDED,
        SimulationRunStatus.FAILED,
        SimulationRunStatus.REJECTED,
        SimulationRunStatus.CANCELLED,
    ],
)
async def test_non_executable_runs_cannot_be_claimed(
    backend: Backend, status: SimulationRunStatus
) -> None:
    run = await _persisted(backend, status)
    before = await backend.snapshot()
    assert await backend.store.acquire_execution(run.run_id, "worker-1", uuid4()) is None
    assert await backend.snapshot() == before


async def test_stale_or_foreign_fencing_cannot_change_the_run(backend: Backend) -> None:
    run = await _persisted(backend, SimulationRunStatus.CREATED)
    claim = await backend.store.acquire_execution(run.run_id, "worker-1", uuid4())
    assert claim is not None
    before = await backend.snapshot()

    for owner, token in (("worker-2", claim.fencing_token), ("worker-1", claim.fencing_token + 7)):
        with pytest.raises(GraphEngineError):
            await backend.store.mark_waiting_approval(run.run_id, owner, token)
        with pytest.raises(GraphEngineError):
            await backend.store.fail_execution(run.run_id, owner, token, "STALE_WORKER")
        with pytest.raises(GraphEngineError):
            await backend.store.reject_execution(run.run_id, owner, token)
        with pytest.raises(GraphEngineError):
            await backend.store.cancel_execution(run.run_id, owner, token)
    assert await backend.snapshot() == before
    assert (await backend.store.get_run(run.run_id)).status is SimulationRunStatus.RUNNING


async def test_terminal_run_cannot_be_resurrected_by_any_operation(backend: Backend) -> None:
    run = await _persisted(backend, SimulationRunStatus.SUCCEEDED)
    before = await backend.snapshot()
    store: Any = backend.store  # update_status lives on the repository port, not OperationalStore
    attempts = (
        store.update_status(run.run_id, SimulationRunStatus.RUNNING),
        store.decide(run.run_id, ApprovalDecision.APPROVED, "alice", "Trying to reopen it."),
        store.acquire_execution(run.run_id, "worker-1", uuid4()),
    )
    for attempt in attempts:
        try:
            outcome = await attempt
        except GraphEngineError:
            continue
        assert outcome is None  # a claim attempt returns None rather than raising
    try:
        await store.request_cancellation(run.run_id, "alice")
    except GraphEngineError:
        pass
    assert await backend.snapshot() == before


async def test_checkpoint_for_an_unknown_run_is_not_written(backend: Backend) -> None:
    before = await backend.snapshot()
    ghost = WorkflowCheckpoint(run_id=uuid4(), checkpoint_version=1, state={"stage": "recon"})
    with pytest.raises(OperationalStoreError):
        await backend.store.save_checkpoint(ghost)
    assert await backend.snapshot() == before


async def test_operations_on_an_unknown_run_create_nothing(backend: Backend) -> None:
    before = await backend.snapshot()
    ghost = uuid4()
    store: Any = backend.store
    with pytest.raises(OperationalStoreError):
        await store.get_run(ghost)
    with pytest.raises(OperationalStoreError):
        await store.decide(ghost, ApprovalDecision.APPROVED, "alice", "Reviewed in detail here.")
    with pytest.raises(OperationalStoreError):
        await store.update_status(ghost, SimulationRunStatus.RUNNING)
    assert await backend.snapshot() == before


async def test_duplicate_run_id_cannot_overwrite_an_existing_run(backend: Backend) -> None:
    run = await _persisted(backend, SimulationRunStatus.WAITING_APPROVAL)
    before = await backend.snapshot()
    impostor = run.model_copy(update={"created_by": "mallory", "status": SimulationRunStatus.CREATED})
    with pytest.raises(GraphEngineError):
        await backend.store.create_run(impostor)
    assert await backend.snapshot() == before


async def test_idempotent_create_cannot_be_rebound_to_another_scenario(backend: Backend) -> None:
    key = "integrity-key-0001"
    first, created = await backend.store.create_run_idempotent(_run(), key)
    assert created
    before = await backend.snapshot()
    other = _run().model_copy(update={"scenario_id": "another-scenario"})
    with pytest.raises(OperationalStoreError):
        await backend.store.create_run_idempotent(other, key)
    assert await backend.snapshot() == before
    assert UUID(str(first.run_id))
