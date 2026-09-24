"""Durable simulation worker with fenced ownership and cooperative cancellation."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from enum import StrEnum
from time import perf_counter
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from art_sim.domain.exceptions import (
    ApprovalRequiredError,
    GraphEngineError,
    TopologyNotFoundError,
    WorkerStateError,
)
from art_sim.observability.sink import (
    InMemoryOperationalTelemetrySink,
    MetricEvent,
    OperationalMetricName,
    OperationalTelemetrySink,
)
from art_sim.observability.telemetry import MetricsRegistry, Tracer
from art_sim.platform.models import AuditEvent, ExecutionClaim, SimulationRunStatus
from art_sim.platform.ports import OperationalStore
from art_sim.worker.jobs import (
    DeadLetterSink,
    InMemoryDeadLetterSink,
    PoisonJobRecord,
    SimulationJobV1,
)
from art_sim.worker.ports import ScenarioAllowList, ScenarioRepository
from art_sim.worker.retry import (
    RetryPolicy,
    TransientAdapterError,
    retry_transient,
)
from art_sim.worker.workflow import DurableSimulationWorkflow, WorkflowOutcomeStatus


class WorkerSettings(BaseModel):
    """Bounded execution, heartbeat, and poison-job controls."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_seconds: int = Field(default=300, ge=1, le=3600)
    max_recovery_attempts: int = Field(default=3, ge=1, le=10)
    adapter_retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)


class WorkerRunResult(StrEnum):
    """Observable result of one delivery attempt."""

    NOT_CLAIMED = "not_claimed"
    INVALID_JOB = "invalid_job"
    WAITING_APPROVAL = "waiting_approval"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED = "failed"


class SimulationWorker:
    """Execute only valid, fenced, allow-listed Shadow simulation jobs."""

    def __init__(
        self,
        store: OperationalStore,
        catalog: ScenarioAllowList,
        scenarios: ScenarioRepository,
        workflow: DurableSimulationWorkflow,
        *,
        owner_id: str,
        metrics: MetricsRegistry | None = None,
        telemetry: OperationalTelemetrySink | None = None,
        dead_letters: DeadLetterSink | None = None,
        settings: WorkerSettings | None = None,
    ) -> None:
        if not owner_id or len(owner_id) > 96:
            raise ValueError("Worker owner_id is invalid")
        self._store = store
        self._catalog = catalog
        self._scenarios = scenarios
        self._workflow = workflow
        self._owner_id = owner_id
        self._metrics = metrics or MetricsRegistry()
        self._telemetry = telemetry or InMemoryOperationalTelemetrySink()
        self._dead_letters = dead_letters or InMemoryDeadLetterSink()
        self._settings = settings or WorkerSettings()

    @property
    def metrics(self) -> MetricsRegistry:
        """Expose aggregate, non-sensitive worker metrics."""
        return self._metrics

    async def run(self, run_id: UUID) -> WorkerRunResult:
        """Compatibility entry point that builds the current versioned job."""
        run = await self._store.get_run(run_id)
        if run.status not in {
            SimulationRunStatus.CREATED,
            SimulationRunStatus.RUNNING,
            SimulationRunStatus.RESUMING,
        }:
            return WorkerRunResult.NOT_CLAIMED
        attempt = await self._store.next_execution_attempt(run_id)
        return await self.run_job(SimulationJobV1.for_run(run, attempt))

    async def run_serialized(self, payload: bytes | str) -> WorkerRunResult:
        """Decode an untrusted broker payload before touching durable state."""
        try:
            job = SimulationJobV1.decode(payload)
        except WorkerStateError:
            return WorkerRunResult.INVALID_JOB
        return await self.run_job(job)

    async def run_job(self, job: SimulationJobV1) -> WorkerRunResult:
        """Claim and execute one job; duplicate and stale deliveries are safe no-ops."""
        try:
            run = await self._store.get_run(job.run_id)
        except GraphEngineError:
            return WorkerRunResult.INVALID_JOB
        if (
            run.workflow_version != job.workflow_version
            or run.scenario_id != job.scenario_id
        ):
            return WorkerRunResult.INVALID_JOB
        tracer = Tracer(run_id=job.run_id, metrics=self._metrics)
        claim = await self._store.acquire_execution(
            job.run_id,
            self._owner_id,
            tracer.trace_id,
            lease_seconds=self._settings.lease_seconds,
            expected_attempt=job.attempt,
        )
        if claim is None:
            return WorkerRunResult.NOT_CLAIMED
        started = perf_counter()
        heartbeat = asyncio.create_task(
            self._heartbeat(claim),
            name=f"lease-heartbeat-{claim.run.run_id}",
        )
        await self._metric("simulations_started_total", 1.0, tracer)
        try:
            if claim.attempt > 1:
                await self._metric("simulations_recovered_total", 1.0, tracer)
                await self._metric("lease_expirations_total", 1.0, tracer)
            if claim.attempt > self._settings.max_recovery_attempts:
                await self._dead_letters.publish(
                    PoisonJobRecord(
                        run_id=job.run_id,
                        message_id=job.message_id,
                        attempt=claim.attempt,
                        recorded_at=claim.run.updated_at,
                    )
                )
                await self._store.fail_execution(
                    job.run_id,
                    self._owner_id,
                    claim.fencing_token,
                    "MAX_ATTEMPTS_EXCEEDED",
                )
                await self._metric("simulations_failed_total", 1.0, tracer)
                return WorkerRunResult.FAILED
            if not self._catalog.contains(claim.run.scenario_id):
                return await self._fail(claim, tracer, "SCENARIO_NOT_CONFIGURED")
            if claim.run.cancellation_requested:
                return await self._cancel(claim, tracer)
            scenario = await self._scenarios.get(claim.run.scenario_id)
            await self._stage_event(claim, tracer.trace_id, "workflow", True)
            stage_started = perf_counter()
            outcome = await self._workflow.execute(claim.run, scenario, tracer)
            stage_duration = perf_counter() - stage_started
            self._metrics.observe_duration("simulation_stage_duration_seconds", stage_duration)
            await self._metric(
                "simulation_stage_duration_seconds",
                stage_duration,
                tracer,
            )
            await self._stage_event(claim, tracer.trace_id, "workflow", False)
            current = await self._store.get_run(job.run_id)
            if current.cancellation_requested:
                return await self._cancel(claim, tracer)
            if outcome.status is WorkflowOutcomeStatus.WAITING_APPROVAL:
                waiting = await self._store.mark_waiting_approval(
                    job.run_id,
                    self._owner_id,
                    claim.fencing_token,
                )
                if waiting.status is SimulationRunStatus.CANCELLED:
                    await self._metric("simulation_rejected_total", 1.0, tracer)
                    return WorkerRunResult.CANCELLED
                await self._metric("simulation_approval_total", 1.0, tracer)
                return WorkerRunResult.WAITING_APPROVAL
            if outcome.status is WorkflowOutcomeStatus.REJECTED:
                rejected = await self._store.reject_execution(
                    job.run_id,
                    self._owner_id,
                    claim.fencing_token,
                )
                if rejected.status is SimulationRunStatus.CANCELLED:
                    await self._metric("simulation_rejected_total", 1.0, tracer)
                    return WorkerRunResult.CANCELLED
                await self._metric("simulation_rejected_total", 1.0, tracer)
                return WorkerRunResult.REJECTED
            if outcome.artifacts is None:
                raise WorkerStateError("Successful workflow returned no artifacts")
            try:
                await self._store.complete_execution(
                    outcome.artifacts, self._owner_id, claim.fencing_token
                )
            except GraphEngineError:
                await self._metric(
                    "result_persistence_failures_total",
                    1.0,
                    tracer,
                )
                raise
            await self._metric("simulations_succeeded_total", 1.0, tracer)
            return WorkerRunResult.SUCCEEDED
        except TopologyNotFoundError:
            return await self._fail(claim, tracer, "SHADOW_TOPOLOGY_NOT_FOUND")
        except ApprovalRequiredError:
            return await self._fail(claim, tracer, "APPROVAL_STATE_INVALID")
        except WorkerStateError:
            return await self._fail(claim, tracer, "WORKFLOW_EXECUTION_FAILED")
        except GraphEngineError:
            current = await self._store.get_run(claim.run.run_id)
            if current.cancellation_requested:
                return await self._cancel(claim, tracer)
            return await self._fail(claim, tracer, "WORKFLOW_EXECUTION_FAILED")
        except Exception:  # noqa: BLE001 - process boundary persists only a safe code
            return await self._fail(claim, tracer, "WORKFLOW_EXECUTION_FAILED")
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat
            duration = perf_counter() - started
            self._metrics.observe_duration("simulation_duration_seconds", duration)
            await self._metric("simulation_duration_seconds", duration, tracer)

    async def _heartbeat(self, claim: ExecutionClaim) -> None:
        interval = max(0.1, self._settings.lease_seconds / 3)
        while True:
            await asyncio.sleep(interval)
            renewed = await self._store.renew_execution(
                claim.run.run_id,
                self._owner_id,
                claim.fencing_token,
                lease_seconds=self._settings.lease_seconds,
            )
            if not renewed:
                return

    async def _cancel(self, claim: ExecutionClaim, tracer: Tracer) -> WorkerRunResult:
        try:
            await self._store.cancel_execution(
                claim.run.run_id,
                self._owner_id,
                claim.fencing_token,
            )
        except GraphEngineError:
            return WorkerRunResult.NOT_CLAIMED
        await self._metric("simulations_cancelled_total", 1.0, tracer)
        return WorkerRunResult.CANCELLED

    async def _fail(
        self,
        claim: ExecutionClaim,
        tracer: Tracer,
        error_code: str,
    ) -> WorkerRunResult:
        try:
            failed = await self._store.fail_execution(
                claim.run.run_id,
                self._owner_id,
                claim.fencing_token,
                error_code,
            )
        except GraphEngineError:
            return WorkerRunResult.NOT_CLAIMED
        if failed.status is SimulationRunStatus.CANCELLED:
            await self._metric("simulation_rejected_total", 1.0, tracer)
            return WorkerRunResult.CANCELLED
        await self._metric("simulations_failed_total", 1.0, tracer)
        return WorkerRunResult.FAILED

    async def _stage_event(
        self,
        claim: ExecutionClaim,
        trace_id: UUID,
        stage: str,
        started: bool,
    ) -> None:
        await self._store.append_worker_event(
            AuditEvent(
                run_id=claim.run.run_id,
                event_type=(
                    "simulation.stage_started" if started else "simulation.stage_completed"
                ),
                actor=f"worker:{self._owner_id}",
                status="pending" if started else "succeeded",
                metadata={
                    "stage": stage,
                    "trace_id": str(trace_id),
                    "fencing_token": str(claim.fencing_token),
                },
            ),
            self._owner_id,
            claim.fencing_token,
        )

    async def _metric(self, name: str, value: float, tracer: Tracer) -> None:
        if name.endswith("_total"):
            self._metrics.increment(name, int(value))
        event = MetricEvent(
            name=OperationalMetricName(name),
            value=value,
            run_id=tracer.run_id,
            trace_id=tracer.trace_id,
            worker_id=self._owner_id,
        )

        async def emit() -> None:
            await self._telemetry.emit_metric(event)

        try:
            await retry_transient(emit, self._settings.adapter_retry_policy)
        except TransientAdapterError:
            self._metrics.increment("telemetry_delivery_failed_total")
