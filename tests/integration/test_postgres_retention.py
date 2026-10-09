"""Integration tests for PostgresOperationalStore's retention-purge methods.

Requires a reachable PostgreSQL (set ART_PG_TEST_DSN, or run the default dev container at
postgresql://postgres:devpw@127.0.0.1:55432/artsim). Skipped if no database is reachable.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest

from art_sim.adapters.postgres_store import PostgresOperationalStore
from art_sim.platform.models import SimulationRun, SimulationRunStatus, WorkflowCheckpoint

DSN = os.getenv("ART_PG_TEST_DSN", "postgresql://postgres:devpw@127.0.0.1:55432/artsim")


async def _reachable() -> bool:
    try:
        conn = await asyncpg.connect(DSN, timeout=3)
    except (OSError, asyncpg.PostgresError):
        return False
    await conn.close()
    return True


@pytest.fixture
async def store() -> AsyncGenerator[PostgresOperationalStore]:
    if not await _reachable():
        pytest.skip("No PostgreSQL reachable for integration tests")
    pool = await asyncpg.create_pool(DSN, min_size=1, max_size=8)
    adapter = PostgresOperationalStore(pool)
    await adapter.initialize()
    async with pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE simulation_reviews, simulation_results, audit_events, api_idempotency, "
            "workflow_checkpoints, worker_leases, simulation_runs RESTART IDENTITY CASCADE"
        )
    yield adapter
    await adapter.close()


def _run(status: SimulationRunStatus) -> SimulationRun:
    return SimulationRun(
        scenario_id="retention-test",
        graph_version="g-v1",
        workflow_version="v1",
        created_by="retention-test",
        status=status,
    )


async def _backdate_run(store: PostgresOperationalStore, run_id: object, when: datetime) -> None:
    async with store._pool.acquire() as conn:
        await conn.execute("UPDATE simulation_runs SET updated_at=$1 WHERE run_id=$2", when, run_id)


async def test_terminal_run_past_retention_is_purged(store: PostgresOperationalStore) -> None:
    run = _run(SimulationRunStatus.COMPLETED)
    await store.create_run(run)
    await _backdate_run(store, run.run_id, datetime.now(UTC) - timedelta(days=100))

    cutoff = datetime.now(UTC) - timedelta(days=90)
    count = await store.purge_expired_runs(older_than=cutoff, dry_run=False)
    assert count == 1
    with pytest.raises(Exception):  # noqa: B017 - OperationalStoreError, imported lazily below
        await store.get_run(run.run_id)


async def test_dry_run_counts_without_deleting(store: PostgresOperationalStore) -> None:
    run = _run(SimulationRunStatus.COMPLETED)
    await store.create_run(run)
    await _backdate_run(store, run.run_id, datetime.now(UTC) - timedelta(days=100))

    cutoff = datetime.now(UTC) - timedelta(days=90)
    count = await store.purge_expired_runs(older_than=cutoff, dry_run=True)
    assert count == 1
    # Still present: a dry run must never delete.
    fetched = await store.get_run(run.run_id)
    assert fetched.run_id == run.run_id


async def test_non_terminal_run_is_never_purged(store: PostgresOperationalStore) -> None:
    run = _run(SimulationRunStatus.RUNNING)
    await store.create_run(run)
    await _backdate_run(store, run.run_id, datetime.now(UTC) - timedelta(days=9999))

    cutoff = datetime.now(UTC) - timedelta(days=1)
    count = await store.purge_expired_runs(older_than=cutoff, dry_run=False)
    assert count == 0
    fetched = await store.get_run(run.run_id)
    assert fetched.run_id == run.run_id


async def test_recent_terminal_run_is_not_purged(store: PostgresOperationalStore) -> None:
    run = _run(SimulationRunStatus.COMPLETED)
    await store.create_run(run)  # updated_at defaults to "now"

    cutoff = datetime.now(UTC) - timedelta(days=90)
    count = await store.purge_expired_runs(older_than=cutoff, dry_run=False)
    assert count == 0


async def test_purging_a_run_deletes_its_dependent_rows(store: PostgresOperationalStore) -> None:
    run = _run(SimulationRunStatus.COMPLETED)
    await store.create_run(run)
    await store.save_checkpoint(
        WorkflowCheckpoint(run_id=run.run_id, state={}, checkpoint_version=1)
    )
    await _backdate_run(store, run.run_id, datetime.now(UTC) - timedelta(days=100))

    cutoff = datetime.now(UTC) - timedelta(days=90)
    await store.purge_expired_runs(older_than=cutoff, dry_run=False)

    async with store._pool.acquire() as conn:
        remaining = await conn.fetchval(
            "SELECT count(*) FROM workflow_checkpoints WHERE run_id=$1", run.run_id
        )
    assert remaining == 0


async def test_checkpoint_purge_respects_its_own_window(store: PostgresOperationalStore) -> None:
    run = _run(SimulationRunStatus.COMPLETED)
    await store.create_run(run)
    await store.save_checkpoint(
        WorkflowCheckpoint(run_id=run.run_id, state={}, checkpoint_version=1)
    )
    async with store._pool.acquire() as conn:
        await conn.execute(
            "UPDATE workflow_checkpoints SET created_at=$1 WHERE run_id=$2",
            datetime.now(UTC) - timedelta(days=100),
            run.run_id,
        )

    cutoff = datetime.now(UTC) - timedelta(days=30)
    count = await store.purge_expired_checkpoints(older_than=cutoff, dry_run=False)
    assert count == 1
    with pytest.raises(Exception):  # noqa: B017
        await store.load_checkpoint(run.run_id)
    # The run itself is untouched — only its checkpoint was purged.
    fetched = await store.get_run(run.run_id)
    assert fetched.run_id == run.run_id


async def test_result_purge_respects_its_own_window(store: PostgresOperationalStore) -> None:
    run = _run(SimulationRunStatus.COMPLETED)
    await store.create_run(run)
    async with store._pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO simulation_results(run_id, workflow_version, payload, created_at) "
            "VALUES ($1, 'v1', '{}', $2)",
            run.run_id,
            datetime.now(UTC) - timedelta(days=100),
        )

    cutoff = datetime.now(UTC) - timedelta(days=90)
    count = await store.purge_expired_results(older_than=cutoff, dry_run=False)
    assert count == 1
    async with store._pool.acquire() as conn:
        remaining = await conn.fetchval(
            "SELECT count(*) FROM simulation_results WHERE run_id=$1", run.run_id
        )
    assert remaining == 0
