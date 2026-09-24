"""Durable worker, ownership, recovery, HITL, and Shadow-only regressions."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from art_sim.api.services import ScenarioCatalog
from art_sim.observability.telemetry import Tracer
from art_sim.platform.checkpoint import sqlite_langgraph_checkpointer
from art_sim.platform.models import SimulationRun, SimulationRunStatus
from art_sim.platform.sqlite import OperationalStoreError, SqliteOperationalStore
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus, VerificationStatus
from art_sim.worker.fixtures import shadow_demo_scenario
from art_sim.worker.models import SimulationScenario
from art_sim.worker.shadow import InMemoryScenarioRepository, ShadowGraphRepository
from art_sim.worker.worker import SimulationWorker, WorkerRunResult
from art_sim.worker.workflow import DurableSimulationWorkflow


def _run(scenario: SimulationScenario) -> SimulationRun:
    return SimulationRun(
        scenario_id=scenario.scenario_id,
        graph_version="unresolved",
        workflow_version="worker-v1",
        created_by="operator",
        request_id="request-worker-test",
    )


def _worker(
    store: SqliteOperationalStore,
    scenario: SimulationScenario,
    workflow: DurableSimulationWorkflow,
    owner: str,
) -> SimulationWorker:
    return SimulationWorker(
        store,
        ScenarioCatalog((scenario.scenario_id,)),
        InMemoryScenarioRepository((scenario,)),
        workflow,
        owner_id=owner,
    )


async def test_created_running_succeeded_and_all_results_persist(tmp_path: Path) -> None:
    database = tmp_path / "worker.sqlite3"
    store = SqliteOperationalStore(database)
    await store.initialize()
    scenario = shadow_demo_scenario(requires_approval=False)
    run = _run(scenario)
    await store.create_run(run)

    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, b"a" * 32), "one")
        assert await worker.run(run.run_id) is WorkerRunResult.SUCCEEDED

    persisted = await store.get_run(run.run_id)
    result = await store.get_result(run.run_id)
    assert persisted.status is SimulationRunStatus.SUCCEEDED
    assert persisted.graph_version == scenario.graph_version
    assert result.risk.score == persisted.risk_before
    assert result.attack_paths
    assert result.blast_radius.total_assets > 0
    assert result.remediations[0].simulated_only
    assert result.remediation_artifacts[0].file_path
    assert result.verification.status is VerificationStatus.VERIFIED
    assert "# Security Simulation Report" in result.report_markdown
    events = await store.list_events(run.run_id)
    assert {event.event_type for event in events} >= {
        "simulation.created",
        "simulation.started",
        "simulation.stage_started",
        "simulation.stage_completed",
        "simulation.completed",
    }


async def test_hitl_survives_restart_then_resumes_to_success(tmp_path: Path) -> None:
    database = tmp_path / "hitl.sqlite3"
    scenario = shadow_demo_scenario()
    first_store = SqliteOperationalStore(database)
    await first_store.initialize()
    run = _run(scenario)
    await first_store.create_run(run)

    async with sqlite_langgraph_checkpointer(database) as saver:
        first = _worker(
            first_store,
            scenario,
            DurableSimulationWorkflow(saver, b"b" * 32),
            "first",
        )
        assert await first.run(run.run_id) is WorkerRunResult.WAITING_APPROVAL
    assert (await first_store.get_run(run.run_id)).status is SimulationRunStatus.WAITING_APPROVAL

    second_store = SqliteOperationalStore(database)
    await second_store.initialize()
    decided = await second_store.decide(run.run_id, ApprovalDecision.APPROVED, "approver")
    assert decided.status is SimulationRunStatus.RESUMING
    async with sqlite_langgraph_checkpointer(database) as saver:
        second = _worker(
            second_store,
            scenario,
            DurableSimulationWorkflow(saver, b"b" * 32),
            "second",
        )
        assert await second.run(run.run_id) is WorkerRunResult.SUCCEEDED

    final = await second_store.get_run(run.run_id)
    result = await second_store.get_result(run.run_id)
    assert final.status is SimulationRunStatus.SUCCEEDED
    assert result.approval is not None
    assert result.approval.operator == "approver"
    assert result.verification.status is VerificationStatus.VERIFIED


async def test_rejection_after_restart_is_terminal_and_has_no_fake_results(
    tmp_path: Path,
) -> None:
    database = tmp_path / "reject.sqlite3"
    scenario = shadow_demo_scenario()
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, b"c" * 32), "one")
        assert await worker.run(run.run_id) is WorkerRunResult.WAITING_APPROVAL
    await store.decide(run.run_id, ApprovalDecision.REJECTED, "reviewer")
    async with sqlite_langgraph_checkpointer(database) as saver:
        restarted = _worker(
            store,
            scenario,
            DurableSimulationWorkflow(saver, b"c" * 32),
            "two",
        )
        assert await restarted.run(run.run_id) is WorkerRunResult.REJECTED
    final = await store.get_run(run.run_id)
    assert final.status is SimulationRunStatus.REJECTED
    assert final.approval_status is ApprovalStatus.REJECTED
    with pytest.raises(OperationalStoreError, match="does not exist"):
        await store.get_result(run.run_id)


async def test_two_workers_have_one_durable_owner_and_terminal_run_does_not_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "concurrent.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        first = _worker(store, scenario, DurableSimulationWorkflow(saver, b"d" * 32), "one")
        second = _worker(store, scenario, DurableSimulationWorkflow(saver, b"d" * 32), "two")
        outcomes = await asyncio.gather(first.run(run.run_id), second.run(run.run_id))
        assert outcomes.count(WorkerRunResult.SUCCEEDED) == 1
        assert outcomes.count(WorkerRunResult.NOT_CLAIMED) == 1
        assert await first.run(run.run_id) is WorkerRunResult.NOT_CLAIMED
    events = await store.list_events(run.run_id)
    assert sum(event.event_type == "simulation.started" for event in events) == 1


async def test_unknown_scenario_fails_with_safe_code(tmp_path: Path) -> None:
    database = tmp_path / "unknown.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario).model_copy(update={"scenario_id": "missing-scenario"})
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, b"e" * 32), "one")
        assert await worker.run(run.run_id) is WorkerRunResult.FAILED
    failed = await store.get_run(run.run_id)
    assert failed.status is SimulationRunStatus.FAILED
    assert failed.error_code == "SCENARIO_NOT_CONFIGURED"


class _ProcessCrash(BaseException):
    """Test-only abrupt process loss that bypasses normal Exception handling."""


class _CrashBeforeCheckpoint(DurableSimulationWorkflow):
    async def execute(
        self,
        run: SimulationRun,
        scenario: SimulationScenario,
        tracer: Tracer,
    ) -> Any:
        del run, scenario, tracer
        raise _ProcessCrash


class _CrashAfterCheckpoint(DurableSimulationWorkflow):
    async def execute(
        self,
        run: SimulationRun,
        scenario: SimulationScenario,
        tracer: Tracer,
    ) -> Any:
        await super().execute(run, scenario, tracer)
        raise _ProcessCrash


@pytest.mark.parametrize("after_checkpoint", [False, True])
async def test_expired_lease_recovers_after_process_crash(
    tmp_path: Path,
    after_checkpoint: bool,
) -> None:
    database = tmp_path / f"crash-{after_checkpoint}.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    first_store = SqliteOperationalStore(database)
    await first_store.initialize()
    run = _run(scenario)
    await first_store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        workflow_type = _CrashAfterCheckpoint if after_checkpoint else _CrashBeforeCheckpoint
        crashing = _worker(first_store, scenario, workflow_type(saver, b"f" * 32), "crashed")
        with pytest.raises(_ProcessCrash):
            await crashing.run(run.run_id)
    assert (await first_store.get_run(run.run_id)).status is SimulationRunStatus.RUNNING

    future = datetime.now(UTC) + timedelta(minutes=10)
    recovered_store = SqliteOperationalStore(database, clock=lambda: future)
    await recovered_store.initialize()
    async with sqlite_langgraph_checkpointer(database) as saver:
        recovered = _worker(
            recovered_store,
            scenario,
            DurableSimulationWorkflow(saver, b"f" * 32),
            "recovered",
        )
        assert await recovered.run(run.run_id) is WorkerRunResult.SUCCEEDED
    assert (await recovered_store.get_run(run.run_id)).status is SimulationRunStatus.SUCCEEDED


async def test_shadow_repository_rejects_writes_and_graph_remains_isolated() -> None:
    scenario = shadow_demo_scenario(requires_approval=False)
    repository = ShadowGraphRepository(scenario.graph)
    original = scenario.graph.model_dump_json()
    with pytest.raises(Exception, match="scope policy"):
        await repository.upsert_asset(scenario.graph.assets[0])
    assert scenario.graph.model_dump_json() == original
    assert all(asset.environment.value == "shadow" for asset in scenario.graph.assets)


async def test_worker_audit_never_contains_signing_material(tmp_path: Path) -> None:
    database = tmp_path / "redaction.sqlite3"
    secret = b"never-serialize-this-signing-material"
    scenario = shadow_demo_scenario(requires_approval=False)
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, secret), "one")
        await worker.run(run.run_id)
    serialized = "".join(event.model_dump_json() for event in await store.list_events(run.run_id))
    assert secret.decode() not in serialized
