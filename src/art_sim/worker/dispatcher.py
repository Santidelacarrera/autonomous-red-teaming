"""Local and broker-backed activation adapters over durable ownership claims."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import ClassVar
from uuid import UUID

from art_sim.domain.exceptions import ConfigurationError, WorkerStateError
from art_sim.platform.models import SimulationRunStatus
from art_sim.platform.ports import OperationalStore
from art_sim.worker.jobs import CancellationReceipt, DispatchReceipt, SimulationJobV1
from art_sim.worker.ports import BrokerTransport, DispatcherScope
from art_sim.worker.retry import RetryPolicy, retry_transient
from art_sim.worker.worker import SimulationWorker

_EXECUTABLE = frozenset(
    {
        SimulationRunStatus.CREATED,
        SimulationRunStatus.RUNNING,
        SimulationRunStatus.RESUMING,
    }
)


class LocalSimulationDispatcher:
    """Wake an in-process worker; SQLite CAS/leases, not this queue, prevent duplicates."""

    deployment_scope: ClassVar[DispatcherScope] = DispatcherScope.PROCESS

    def __init__(
        self,
        store: OperationalStore,
        *,
        concurrency: int = 1,
        recovery_interval_seconds: float = 5.0,
    ) -> None:
        if not 1 <= concurrency <= 16 or not 0.1 <= recovery_interval_seconds <= 60.0:
            raise ValueError("Local dispatcher settings are invalid")
        self._store = store
        self._concurrency = concurrency
        self._recovery_interval = recovery_interval_seconds
        self._queue: asyncio.Queue[SimulationJobV1] = asyncio.Queue()
        self._worker: SimulationWorker | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._stopping = asyncio.Event()
        self._accepting = False

    async def start(self, worker: SimulationWorker) -> None:
        """Start consumers and recover persisted executable runs after process restart."""
        if self._tasks:
            raise ConfigurationError("Local simulation dispatcher is already running")
        self._worker = worker
        self._stopping.clear()
        self._accepting = True
        self._tasks = [
            asyncio.create_task(self._consume(), name=f"simulation-worker-{index}")
            for index in range(self._concurrency)
        ]
        self._tasks.append(
            asyncio.create_task(self._recover_loop(), name="simulation-recovery")
        )
        await self._enqueue_recoverable()

    async def dispatch(self, run_id: UUID) -> DispatchReceipt:
        """Build and enqueue a versioned job without executing it inline."""
        if self._worker is None or not self._accepting:
            raise ConfigurationError("Local simulation dispatcher has not started")
        job = await _job_for_run(self._store, run_id)
        await self._queue.put(job)
        return DispatchReceipt(run_id=run_id, message_id=job.message_id, accepted=True)

    async def cancel(self, run_id: UUID) -> CancellationReceipt:
        """Wake recovery for a cooperative cancel; never terminate worker tasks."""
        run = await self._store.get_run(run_id)
        if run.status in _EXECUTABLE and self._accepting:
            await self._queue.put(await _job_for_run(self._store, run_id))
        return CancellationReceipt(
            run_id=run_id,
            accepted=True,
            duplicate=run.status is SimulationRunStatus.CANCELLED,
        )

    async def drain(self) -> None:
        """Wait until all currently queued local deliveries have been processed."""
        await self._queue.join()

    async def stop(self) -> None:
        """Drain active work, then cancel only idle local consumer tasks."""
        if not self._tasks:
            return
        self._accepting = False
        await self._queue.join()
        self._stopping.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
        self._worker = None

    async def _consume(self) -> None:
        while not self._stopping.is_set():
            job = await self._queue.get()
            try:
                worker = self._worker
                if worker is None:
                    raise ConfigurationError("Local simulation worker is unavailable")
                await worker.run_job(job)
            finally:
                self._queue.task_done()

    async def _recover_loop(self) -> None:
        while not self._stopping.is_set():
            await asyncio.sleep(self._recovery_interval)
            await self._enqueue_recoverable()

    async def _enqueue_recoverable(self) -> None:
        for status in (
            SimulationRunStatus.CREATED,
            SimulationRunStatus.RUNNING,
            SimulationRunStatus.RESUMING,
        ):
            offset = 0
            while True:
                runs = await self._store.list_runs(limit=200, offset=offset, status=status)
                for run in runs:
                    try:
                        await self._queue.put(await _job_for_run(self._store, run.run_id))
                    except WorkerStateError:
                        continue
                if len(runs) < 200:
                    break
                offset += len(runs)


class BrokerSimulationDispatcher:
    """Publish versioned jobs through an injected durable broker transport."""

    deployment_scope: ClassVar[DispatcherScope] = DispatcherScope.DISTRIBUTED

    def __init__(
        self,
        store: OperationalStore,
        transport: BrokerTransport,
        *,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self._store = store
        self._transport = transport
        self._retry_policy = retry_policy or RetryPolicy()

    async def dispatch(self, run_id: UUID) -> DispatchReceipt:
        """Publish idempotently using the stable message ID as deduplication key."""
        job = await _job_for_run(self._store, run_id)

        async def publish() -> bool:
            return await self._transport.publish(job, str(job.message_id))

        accepted = await retry_transient(publish, self._retry_policy)
        return DispatchReceipt(
            run_id=run_id,
            message_id=job.message_id,
            accepted=accepted,
            duplicate=not accepted,
        )

    async def cancel(self, run_id: UUID) -> CancellationReceipt:
        """Publish a cooperative signal keyed only by safe correlation data."""
        run = await self._store.get_run(run_id)

        async def publish() -> bool:
            return await self._transport.publish_cancellation(
                run_id,
                run.request_id or str(run_id),
            )

        accepted = await retry_transient(publish, self._retry_policy)
        return CancellationReceipt(
            run_id=run_id,
            accepted=accepted,
            duplicate=not accepted,
        )


async def _job_for_run(store: OperationalStore, run_id: UUID) -> SimulationJobV1:
    """Resolve the current run and its next durable execution attempt."""
    run = await store.get_run(run_id)
    if run.status not in _EXECUTABLE:
        raise WorkerStateError("Simulation run is not executable")
    attempt = await store.next_execution_attempt(run_id)
    return SimulationJobV1.for_run(run, attempt)
