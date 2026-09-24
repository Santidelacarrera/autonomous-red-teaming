"""Restart, integrity, and transactional-approval tests for the SQLite operational store."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any, TypedDict
from uuid import uuid4

import pytest
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import START, StateGraph

from art_sim.domain.exceptions import ApprovalRequiredError
from art_sim.platform.checkpoint import sqlite_langgraph_checkpointer
from art_sim.platform.models import SimulationRun, SimulationRunStatus, WorkflowCheckpoint
from art_sim.platform.sqlite import (
    CheckpointCorruptionError,
    OperationalStoreError,
    SqliteOperationalStore,
)
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus


async def _waiting_run(store: SqliteOperationalStore) -> SimulationRun:
    """Create a persisted run at the only state accepted by approval CAS."""
    run = SimulationRun(
        scenario_id="shadow-regression",
        graph_version="test-graph-v1",
        workflow_version="v1",
        created_by="test-operator",
        status=SimulationRunStatus.WAITING_APPROVAL,
    )
    await store.create_run(run)
    return run


async def test_checkpoint_survives_store_restart(tmp_path: Path) -> None:
    """A second store instance resumes a JSON-safe checkpoint from the same database file."""
    path = tmp_path / "operations.sqlite3"
    first = SqliteOperationalStore(path)
    await first.initialize()
    run = await _waiting_run(first)
    checkpoint = WorkflowCheckpoint(run_id=run.run_id, checkpoint_version=1, state={"node": "approval", "attempt": 1})
    await first.save_checkpoint(checkpoint)

    second = SqliteOperationalStore(path)
    await second.initialize()
    assert await second.load_checkpoint(run.run_id) == checkpoint


async def test_native_langgraph_sqlite_saver_resumes_after_worker_restart(tmp_path: Path) -> None:
    """The official saver restores an interrupted graph with a new worker instance."""
    class CounterState(TypedDict):
        count: int

    async def increment(state: CounterState) -> dict[str, int]:
        return {"count": state["count"] + 1}

    def compile_graph(checkpointer: BaseCheckpointSaver[Any]) -> Any:
        builder = StateGraph(CounterState)
        builder.add_node("increment", increment)
        builder.add_edge(START, "increment")
        return builder.compile(checkpointer=checkpointer, interrupt_before=["increment"])

    database_path = tmp_path / "langgraph.sqlite3"
    config = {"configurable": {"thread_id": str(uuid4())}}
    async with sqlite_langgraph_checkpointer(database_path) as first_saver:
        paused = await compile_graph(first_saver).ainvoke({"count": 0}, config)
        assert paused["count"] == 0
    async with sqlite_langgraph_checkpointer(database_path) as second_saver:
        resumed = await compile_graph(second_saver).ainvoke(None, config)
        assert resumed["count"] == 1


async def test_missing_and_tampered_checkpoints_fail_closed(tmp_path: Path) -> None:
    """Missing snapshots and checksum mismatch never deserialize as an approval state."""
    path = tmp_path / "operations.sqlite3"
    store = SqliteOperationalStore(path)
    await store.initialize()
    with pytest.raises(OperationalStoreError, match="does not exist"):
        await store.load_checkpoint(uuid4())
    run = await _waiting_run(store)
    await store.save_checkpoint(WorkflowCheckpoint(run_id=run.run_id, checkpoint_version=1, state={"node": "approval"}))
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE workflow_checkpoints SET payload = ? WHERE run_id = ?", ('{"run_id":"bad"}', str(run.run_id)))
    with pytest.raises(CheckpointCorruptionError):
        await store.load_checkpoint(run.run_id)


async def test_transactional_approval_allows_one_worker_and_appends_evidence(tmp_path: Path) -> None:
    """SQLite BEGIN IMMEDIATE provides one winner for concurrent conflicting decisions."""
    store = SqliteOperationalStore(tmp_path / "operations.sqlite3")
    await store.initialize()
    run = await _waiting_run(store)
    outcomes = await asyncio.gather(
        store.decide(run.run_id, ApprovalDecision.APPROVED, "worker-a"),
        store.decide(run.run_id, ApprovalDecision.REJECTED, "worker-b"),
        return_exceptions=True,
    )
    winners = [result for result in outcomes if isinstance(result, SimulationRun)]
    failures = [result for result in outcomes if isinstance(result, ApprovalRequiredError)]
    assert len(winners) == 1
    assert len(failures) == 1
    assert winners[0].approval_status in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}
    events = await store.list_events(run.run_id)
    assert [event.event_type for event in events] == ["simulation.created", f"approval.{winners[0].approval_status.value}"]


async def test_terminal_run_and_duplicate_run_id_are_rejected(tmp_path: Path) -> None:
    """The store does not silently resurrect terminal runs or overwrite correlation IDs."""
    store = SqliteOperationalStore(tmp_path / "operations.sqlite3")
    await store.initialize()
    run = await _waiting_run(store)
    with pytest.raises(OperationalStoreError, match="already exists"):
        await store.create_run(run)
    rejected = await store.decide(run.run_id, ApprovalDecision.REJECTED, "operator")
    assert rejected.status is SimulationRunStatus.REJECTED
    with pytest.raises(OperationalStoreError, match="Terminal"):
        await store.update_status(run.run_id, SimulationRunStatus.RUNNING)
