"""An interrupted simulation resumes from its durable checkpoint and reaches the same result.

``_ProcessCrash`` derives from ``BaseException`` so it bypasses every ``except Exception`` in the
worker, exactly like a killed process: nothing gets a chance to tidy up. Recovery then happens
the way production does it — a *new* store/worker/saver over the same database file, after the
dead worker's lease expires. The assertions go beyond "it finished":

* work already checkpointed is not repeated (recon runs once, not twice);
* the recovered result is identical to an uninterrupted control run;
* the approval decision survives a crash during resume and is applied exactly once;
* a checkpoint that cannot be trusted fails the run closed instead of guessing.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from art_sim.agents.planner import MitrePathPlanner
from art_sim.agents.recon import ReconAgent
from art_sim.api.services import ScenarioCatalog
from art_sim.observability.telemetry import Tracer
from art_sim.platform.checkpoint import sqlite_langgraph_checkpointer
from art_sim.platform.models import SimulationRun, SimulationRunStatus
from art_sim.platform.sqlite import OperationalStoreError, SqliteOperationalStore
from art_sim.remediation.models import ApprovalDecision, VerificationStatus
from art_sim.worker.fixtures import shadow_demo_scenario
from art_sim.worker.models import SimulationScenario
from art_sim.worker.shadow import InMemoryScenarioRepository
from art_sim.worker.worker import SimulationWorker, WorkerRunResult
from art_sim.worker.workflow import DurableSimulationWorkflow

SECRET = b"r" * 32
# Fields that legitimately differ between two executions of the same scenario.
PER_EXECUTION = ("generated_at", "report_markdown", "run_id", "trace_id")


class _ProcessCrash(BaseException):
    """Abrupt process loss: not an ``Exception``, so no handler in the worker sees it."""


def _run(scenario: SimulationScenario) -> SimulationRun:
    return SimulationRun(
        scenario_id=scenario.scenario_id,
        graph_version="unresolved",
        workflow_version="worker-v1",
        created_by="operator",
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


def _digest(artifacts: Any) -> str:
    """Hash everything semantically meaningful in a result, ignoring per-execution fields."""
    body = artifacts.model_dump(mode="json")
    for key in PER_EXECUTION:
        body.pop(key)
    if body.get("approval"):
        # The human decision's identity and wall-clock time are per-execution by nature.
        for key in ("approval_id", "decided_at"):
            body["approval"].pop(key)
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


async def _control_digest(tmp_path: Path, *, requires_approval: bool) -> str:
    """Run the scenario once, uninterrupted, on its own database."""
    database = tmp_path / "control.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=requires_approval)
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "control")
        outcome = await worker.run(run.run_id)
        if requires_approval:
            assert outcome is WorkerRunResult.WAITING_APPROVAL
            await store.decide(run.run_id, ApprovalDecision.APPROVED, "approver", "Reviewed evidence.")
            outcome = await worker.run(run.run_id)
    assert outcome is WorkerRunResult.SUCCEEDED
    return _digest(await store.get_result(run.run_id))


# ------------------------------------------------------ crash in the middle of the graph


async def test_crash_between_graph_nodes_resumes_without_repeating_finished_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "midgraph.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)

    recon_calls = 0
    real_discover = ReconAgent.discover
    real_plan = MitrePathPlanner.create_plan
    crash_armed = True

    async def counting_discover(self: ReconAgent, *args: Any, **kwargs: Any) -> Any:
        nonlocal recon_calls
        recon_calls += 1
        return await real_discover(self, *args, **kwargs)

    async def crashing_plan(self: MitrePathPlanner, *args: Any, **kwargs: Any) -> Any:
        if crash_armed:
            raise _ProcessCrash
        return await real_plan(self, *args, **kwargs)

    monkeypatch.setattr(ReconAgent, "discover", counting_discover)
    monkeypatch.setattr(MitrePathPlanner, "create_plan", crashing_plan)

    # --- first process: recon completes and is checkpointed, then the process "dies" in planner
    async with sqlite_langgraph_checkpointer(database) as saver:
        crashing = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "doomed")
        with pytest.raises(_ProcessCrash):
            await crashing.run(run.run_id)
    interrupted = await store.get_run(run.run_id)
    assert interrupted.status is SimulationRunStatus.RUNNING  # nobody finalized it
    assert recon_calls == 1
    with pytest.raises(OperationalStoreError):
        await store.get_result(run.run_id)  # no partial result was published

    # --- the checkpoint itself shows the graph stopped *before* the planner
    async with sqlite_langgraph_checkpointer(database) as saver:
        from art_sim.agents.graph import AttackSimulationGraph
        from art_sim.agents.supervisor import SupervisorAgent
        from art_sim.security.sanitizer import PromptInjectionSanitizer
        from art_sim.worker.shadow import ShadowGraphRepository

        graph = AttackSimulationGraph(
            ReconAgent(ShadowGraphRepository(scenario.graph), PromptInjectionSanitizer()),
            MitrePathPlanner(),
            SupervisorAgent(),
        ).compile(saver)
        snapshot = await graph.aget_state({"configurable": {"thread_id": f"{run.run_id}:attack"}})
    assert snapshot.next == ("planner",)
    assert snapshot.values["attack_path"] is not None  # recon output survived the crash

    # --- recovery: new process, lease expired, planner no longer crashes
    crash_armed = False
    later = datetime.now(UTC) + timedelta(minutes=10)
    recovered_store = SqliteOperationalStore(database, clock=lambda: later)
    await recovered_store.initialize()
    async with sqlite_langgraph_checkpointer(database) as saver:
        recovered = _worker(
            recovered_store, scenario, DurableSimulationWorkflow(saver, SECRET), "recovery"
        )
        assert await recovered.run(run.run_id) is WorkerRunResult.SUCCEEDED

    assert recon_calls == 1, "recon must resume from the checkpoint, not run again"
    final = await recovered_store.get_run(run.run_id)
    assert final.status is SimulationRunStatus.SUCCEEDED
    result = await recovered_store.get_result(run.run_id)
    assert result.verification.status is VerificationStatus.VERIFIED

    # --- and the outcome is indistinguishable from a run that was never interrupted
    monkeypatch.undo()
    assert _digest(result) == await _control_digest(tmp_path, requires_approval=False)

    events = [e.event_type for e in await recovered_store.list_events(run.run_id)]
    assert events.count("simulation.completed") == 1


async def test_a_second_recovery_of_a_finished_run_changes_nothing(tmp_path: Path) -> None:
    """Re-delivery after success (a late retry, a duplicate message) is a safe no-op."""
    database = tmp_path / "idempotent.sqlite3"
    scenario = shadow_demo_scenario(requires_approval=False)
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "one")
        assert await worker.run(run.run_id) is WorkerRunResult.SUCCEEDED
        first = (await store.get_result(run.run_id)).model_dump_json()
        assert await worker.run(run.run_id) is WorkerRunResult.NOT_CLAIMED
    assert (await store.get_result(run.run_id)).model_dump_json() == first


# ----------------------------------------------------- crash while a human decision is pending


async def test_crash_after_approval_was_applied_resumes_and_applies_it_exactly_once(
    tmp_path: Path,
) -> None:
    database = tmp_path / "approval-crash.sqlite3"
    scenario = shadow_demo_scenario()
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)

    async with sqlite_langgraph_checkpointer(database) as saver:
        first = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "first")
        assert await first.run(run.run_id) is WorkerRunResult.WAITING_APPROVAL
    await store.decide(run.run_id, ApprovalDecision.APPROVED, "approver", "Reviewed evidence.")

    class _CrashAfterResume(DurableSimulationWorkflow):
        async def execute(self, run: SimulationRun, scenario: SimulationScenario, tracer: Tracer) -> Any:
            await super().execute(run, scenario, tracer)  # approval node + verification checkpointed
            raise _ProcessCrash

    async with sqlite_langgraph_checkpointer(database) as saver:
        crashing = _worker(store, scenario, _CrashAfterResume(saver, SECRET), "crashing")
        with pytest.raises(_ProcessCrash):
            await crashing.run(run.run_id)
    # Claiming a RESUMING run re-enters RUNNING; the crash left it there, un-finalized.
    assert (await store.get_run(run.run_id)).status is SimulationRunStatus.RUNNING

    later = datetime.now(UTC) + timedelta(minutes=10)
    recovered_store = SqliteOperationalStore(database, clock=lambda: later)
    await recovered_store.initialize()
    async with sqlite_langgraph_checkpointer(database) as saver:
        recovered = _worker(recovered_store, scenario, DurableSimulationWorkflow(saver, SECRET), "recovery")
        assert await recovered.run(run.run_id) is WorkerRunResult.SUCCEEDED

    result = await recovered_store.get_result(run.run_id)
    assert result.approval is not None and result.approval.operator == "approver"
    assert _digest(result) == await _control_digest(tmp_path, requires_approval=True)
    approvals = [
        e for e in await recovered_store.list_events(run.run_id) if e.event_type == "simulation.approved"
    ]
    assert len(approvals) == 1  # the human decision was recorded and applied once


async def test_waiting_run_survives_restart_without_losing_its_review_window_anchor(
    tmp_path: Path,
) -> None:
    database = tmp_path / "anchor.sqlite3"
    scenario = shadow_demo_scenario()
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "one")
        assert await worker.run(run.run_id) is WorkerRunResult.WAITING_APPROVAL
    anchor = (await store.get_run(run.run_id)).approval_requested_at
    assert anchor is not None

    # A restart long after the review began must neither reset nor extend the window.
    far_future = anchor + timedelta(days=3)
    restarted = SqliteOperationalStore(
        database, clock=lambda: far_future, approval_ttl=timedelta(hours=24)
    )
    await restarted.initialize()
    assert (await restarted.get_run(run.run_id)).approval_requested_at == anchor
    from art_sim.domain.exceptions import ApprovalExpiredError

    with pytest.raises(ApprovalExpiredError):
        await restarted.decide(run.run_id, ApprovalDecision.APPROVED, "approver", "Reviewed evidence.")


# --------------------------------------------------------------- untrusted checkpoints


async def test_wiped_langgraph_checkpoint_after_approval_fails_closed(tmp_path: Path) -> None:
    """If the signed approval state is gone, the worker must not re-derive an approval."""
    database = tmp_path / "wiped.sqlite3"
    scenario = shadow_demo_scenario()
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "one")
        assert await worker.run(run.run_id) is WorkerRunResult.WAITING_APPROVAL
    await store.decide(run.run_id, ApprovalDecision.APPROVED, "approver", "Reviewed evidence.")

    connection = sqlite3.connect(database)
    try:
        connection.execute("DELETE FROM checkpoints")
        connection.execute("DELETE FROM writes")
        connection.commit()
    finally:
        connection.close()

    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "two")
        outcome = await worker.run(run.run_id)

    assert outcome is not WorkerRunResult.SUCCEEDED
    assert (await store.get_run(run.run_id)).status is not SimulationRunStatus.SUCCEEDED
    with pytest.raises(OperationalStoreError):
        await store.get_result(run.run_id)  # nothing was published on an unverifiable decision


async def test_resuming_with_a_different_signing_secret_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "rotated.sqlite3"
    scenario = shadow_demo_scenario()
    store = SqliteOperationalStore(database)
    await store.initialize()
    run = _run(scenario)
    await store.create_run(run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        worker = _worker(store, scenario, DurableSimulationWorkflow(saver, SECRET), "one")
        assert await worker.run(run.run_id) is WorkerRunResult.WAITING_APPROVAL
    await store.decide(run.run_id, ApprovalDecision.APPROVED, "approver", "Reviewed evidence.")
    async with sqlite_langgraph_checkpointer(database) as saver:
        # First process completed the approval node under SECRET, then died before finalizing.
        class _CrashAfterResume(DurableSimulationWorkflow):
            async def execute(self, run: SimulationRun, scenario: SimulationScenario, tracer: Tracer) -> Any:
                await super().execute(run, scenario, tracer)
                raise _ProcessCrash

        with pytest.raises(_ProcessCrash):
            await _worker(store, scenario, _CrashAfterResume(saver, SECRET), "two").run(run.run_id)

    later = datetime.now(UTC) + timedelta(minutes=10)
    recovered_store = SqliteOperationalStore(database, clock=lambda: later)
    await recovered_store.initialize()
    async with sqlite_langgraph_checkpointer(database) as saver:
        # A replica configured with the wrong secret cannot vouch for the stored signature.
        wrong = _worker(recovered_store, scenario, DurableSimulationWorkflow(saver, b"w" * 32), "three")
        assert await wrong.run(run.run_id) is not WorkerRunResult.SUCCEEDED
    with pytest.raises(OperationalStoreError):
        await recovered_store.get_result(run.run_id)
