"""Phase 12 distributed contracts, fencing, retry, poison, and cancellation tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, cast
from uuid import UUID, uuid4

import pytest

from art_sim.api.services import ScenarioCatalog
from art_sim.domain.exceptions import ConfigurationError
from art_sim.platform.checkpoint import sqlite_langgraph_checkpointer
from art_sim.platform.models import AuditEvent, SimulationRun, SimulationRunStatus
from art_sim.platform.sqlite import OperationalStoreError, SqliteOperationalStore
from art_sim.worker.broker import BrokerHealth, BrokerProvider
from art_sim.worker.dispatcher import BrokerSimulationDispatcher, LocalSimulationDispatcher
from art_sim.worker.fixtures import shadow_demo_scenario
from art_sim.worker.jobs import InMemoryDeadLetterSink, SimulationJobV1
from art_sim.worker.retry import RetryPolicy, TransientAdapterError
from art_sim.worker.shadow import InMemoryScenarioRepository
from art_sim.worker.worker import SimulationWorker, WorkerRunResult, WorkerSettings
from art_sim.worker.workflow import DurableSimulationWorkflow


class _BrokerTransport:
    provider: ClassVar[BrokerProvider] = BrokerProvider.REDIS_STREAMS

    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.calls = 0
        self.seen: set[str] = set()

    async def publish(self, job: SimulationJobV1, deduplication_key: str) -> bool:
        self.calls += 1
        if self.calls <= self.failures:
            raise TransientAdapterError("temporary broker failure")
        if deduplication_key in self.seen:
            return False
        self.seen.add(deduplication_key)
        return True

    async def publish_cancellation(self, run_id: UUID, correlation_id: str) -> bool:
        key = f"cancel:{run_id}:{correlation_id}"
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    async def health_check(self) -> BrokerHealth:
        return BrokerHealth(provider=self.provider, ready=True)

    async def close(self) -> None:
        return None


class _ControlledWorker:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run_job(self, job: SimulationJobV1) -> WorkerRunResult:
        del job
        self.started.set()
        await self.release.wait()
        return WorkerRunResult.SUCCEEDED

def _run() -> SimulationRun:
    return SimulationRun(
        scenario_id="shadow-demo",
        graph_version="unresolved",
        workflow_version="worker-v1",
        created_by="phase12-test",
        request_id="phase12-correlation",
    )


async def test_job_contract_is_deterministic_strict_and_secret_free() -> None:
    run = _run()
    first = SimulationJobV1.for_run(run, 1)
    second = SimulationJobV1.for_run(run, 1)
    assert first == second
    assert first.encode() == second.encode()
    assert set(first.model_dump()) == {
        "contract_version",
        "message_id",
        "run_id",
        "workflow_version",
        "scenario_id",
        "attempt",
        "created_at",
        "correlation_id",
    }
    assert SimulationJobV1.decode(first.encode()) == first
    with pytest.raises(Exception, match="contract is invalid"):
        SimulationJobV1.decode(first.model_dump_json().replace('"1"', '"2"', 1))
    with pytest.raises(Exception, match="contract is invalid"):
        SimulationJobV1.decode(
            first.model_dump_json()[:-1] + ',"authorization":"forbidden"}'
        )
    with pytest.raises(Exception, match="forbidden field"):
        AuditEvent(
            run_id=run.run_id,
            event_type="simulation.invalid_job",
            actor="worker:test",
            status="failed",
            metadata={"authorization": "forbidden"},
        )


async def test_broker_dispatch_is_idempotent_and_retries_only_transient_failures(
    tmp_path: Path,
) -> None:
    store = SqliteOperationalStore(tmp_path / "broker.sqlite3")
    await store.initialize()
    run = _run()
    await store.create_run(run)
    transport = _BrokerTransport(failures=2)
    dispatcher = BrokerSimulationDispatcher(
        store,
        transport,
        retry_policy=RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=0,
            maximum_backoff_seconds=0,
            jitter_ratio=0,
        ),
    )
    first = await dispatcher.dispatch(run.run_id)
    duplicate = await dispatcher.dispatch(run.run_id)
    assert first.accepted and not first.duplicate
    assert not duplicate.accepted and duplicate.duplicate
    assert first.message_id == duplicate.message_id
    assert transport.calls == 4


async def test_local_dispatcher_graceful_shutdown_drains_and_stops_accepting(
    tmp_path: Path,
) -> None:
    store = SqliteOperationalStore(tmp_path / "graceful.sqlite3")
    await store.initialize()
    run = _run()
    await store.create_run(run)
    dispatcher = LocalSimulationDispatcher(store)
    worker = _ControlledWorker()
    await dispatcher.start(cast(Any, worker))
    await dispatcher.dispatch(run.run_id)
    await worker.started.wait()
    stopping = asyncio.create_task(dispatcher.stop())
    await asyncio.sleep(0)
    assert not stopping.done()
    worker.release.set()
    await stopping
    with pytest.raises(ConfigurationError, match="has not started"):
        await dispatcher.dispatch(run.run_id)


async def test_active_owner_blocks_competitor_and_expiry_advances_fencing(
    tmp_path: Path,
) -> None:
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = SqliteOperationalStore(tmp_path / "fencing.sqlite3", clock=lambda: current[0])
    await store.initialize()
    run = _run()
    await store.create_run(run)
    first = await store.acquire_execution(
        run.run_id,
        "worker-a",
        uuid4(),
        lease_seconds=10,
        expected_attempt=1,
    )
    assert first is not None
    assert await store.acquire_execution(run.run_id, "worker-b", uuid4()) is None

    current[0] += timedelta(seconds=11)
    second = await store.acquire_execution(
        run.run_id,
        "worker-b",
        uuid4(),
        lease_seconds=10,
        expected_attempt=2,
    )
    assert second is not None
    assert second.fencing_token > first.fencing_token
    with pytest.raises(OperationalStoreError, match="does not own"):
        await store.fail_execution(
            run.run_id,
            "worker-a",
            first.fencing_token,
            "STALE_WORKER",
        )
    failed = await store.fail_execution(
        run.run_id,
        "worker-b",
        second.fencing_token,
        "CONTROLLED_FAILURE",
    )
    assert failed.status is SimulationRunStatus.FAILED


async def test_cancellation_is_idempotent_and_never_publishes_results(tmp_path: Path) -> None:
    store = SqliteOperationalStore(tmp_path / "cancel.sqlite3")
    await store.initialize()
    run = _run()
    await store.create_run(run)
    cancelled = await store.request_cancellation(run.run_id, "operator")
    repeated = await store.request_cancellation(run.run_id, "operator")
    assert cancelled.status is repeated.status is SimulationRunStatus.CANCELLED
    with pytest.raises(OperationalStoreError, match="does not exist"):
        await store.get_result(run.run_id)


async def test_running_cancellation_requires_current_fencing_token(tmp_path: Path) -> None:
    store = SqliteOperationalStore(tmp_path / "running-cancel.sqlite3")
    await store.initialize()
    run = _run()
    await store.create_run(run)
    claim = await store.acquire_execution(run.run_id, "worker", uuid4())
    assert claim is not None
    requested = await store.request_cancellation(run.run_id, "operator")
    assert requested.status is SimulationRunStatus.RUNNING
    assert requested.cancellation_requested
    with pytest.raises(OperationalStoreError, match="does not own"):
        await store.cancel_execution(run.run_id, "worker", claim.fencing_token + 1)
    final = await store.cancel_execution(
        run.run_id,
        "worker",
        claim.fencing_token,
    )
    assert final.status is SimulationRunStatus.CANCELLED


async def test_cancellation_wins_race_with_waiting_transition(tmp_path: Path) -> None:
    store = SqliteOperationalStore(tmp_path / "cancel-race.sqlite3")
    await store.initialize()
    run = _run()
    await store.create_run(run)
    claim = await store.acquire_execution(run.run_id, "worker", uuid4())
    assert claim is not None
    await store.request_cancellation(run.run_id, "operator")
    final = await store.mark_waiting_approval(
        run.run_id,
        "worker",
        claim.fencing_token,
    )
    assert final.status is SimulationRunStatus.CANCELLED


async def test_invalid_message_is_rejected_before_durable_state_change(tmp_path: Path) -> None:
    store = SqliteOperationalStore(tmp_path / "invalid-job.sqlite3")
    await store.initialize()
    run = _run()
    await store.create_run(run)
    scenario = shadow_demo_scenario(requires_approval=False)
    worker = SimulationWorker(
        store,
        ScenarioCatalog((scenario.scenario_id,)),
        InMemoryScenarioRepository((scenario,)),
        cast(Any, object()),
        owner_id="worker",
    )
    assert await worker.run_serialized('{"contract_version":"99"}') is WorkerRunResult.INVALID_JOB
    assert (await store.get_run(run.run_id)).status is SimulationRunStatus.CREATED


async def test_max_attempts_becomes_safe_poison_failure(tmp_path: Path) -> None:
    store = SqliteOperationalStore(tmp_path / "poison.sqlite3")
    await store.initialize()
    run = _run()
    await store.create_run(run)
    first = await store.acquire_execution(run.run_id, "old-worker", uuid4())
    assert first is not None
    await store.release_execution(run.run_id, "old-worker", first.fencing_token)
    scenario = shadow_demo_scenario(requires_approval=False)
    dead_letters = InMemoryDeadLetterSink()
    worker = SimulationWorker(
        store,
        ScenarioCatalog((scenario.scenario_id,)),
        InMemoryScenarioRepository((scenario,)),
        cast(Any, object()),
        owner_id="recovery-worker",
        dead_letters=dead_letters,
        settings=WorkerSettings(max_recovery_attempts=1),
    )
    assert await worker.run(run.run_id) is WorkerRunResult.FAILED
    failed = await store.get_run(run.run_id)
    assert failed.error_code == "MAX_ATTEMPTS_EXCEEDED"
    assert dead_letters.records[0].run_id == run.run_id
    assert dead_letters.records[0].reason_code == "MAX_ATTEMPTS_EXCEEDED"
    assert "simulation.poisoned" in {
        event.event_type for event in await store.list_events(run.run_id)
    }


async def test_artifact_version_conflict_rolls_back_without_publication(tmp_path: Path) -> None:
    database = tmp_path / "artifact-conflict.sqlite3"
    store = SqliteOperationalStore(database)
    await store.initialize()
    scenario = shadow_demo_scenario(requires_approval=False)
    source_run = _run()
    await store.create_run(source_run)
    async with sqlite_langgraph_checkpointer(database) as saver:
        source_worker = SimulationWorker(
            store,
            ScenarioCatalog((scenario.scenario_id,)),
            InMemoryScenarioRepository((scenario,)),
            DurableSimulationWorkflow(saver, b"phase12-artifact-signing-material"),
            owner_id="artifact-source",
        )
        assert await source_worker.run(source_run.run_id) is WorkerRunResult.SUCCEEDED
    artifacts = await store.get_result(source_run.run_id)

    target_run = _run().model_copy(update={"workflow_version": "worker-v2"})
    await store.create_run(target_run)
    claim = await store.acquire_execution(target_run.run_id, "artifact-target", uuid4())
    assert claim is not None
    incompatible = artifacts.model_copy(update={"run_id": target_run.run_id})
    with pytest.raises(OperationalStoreError, match="does not match"):
        await store.complete_execution(
            incompatible,
            "artifact-target",
            claim.fencing_token,
        )
    assert (await store.get_run(target_run.run_id)).status is SimulationRunStatus.RUNNING
    with pytest.raises(OperationalStoreError, match="does not exist"):
        await store.get_result(target_run.run_id)
