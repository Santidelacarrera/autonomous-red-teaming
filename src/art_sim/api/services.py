"""Thin application services coordinating durable operational contracts for HTTP."""

from __future__ import annotations

from hashlib import sha256
from uuid import UUID

from art_sim.domain.exceptions import ResultNotAvailableError
from art_sim.platform.models import AuditEvent, SimulationRun, SimulationRunStatus
from art_sim.platform.ports import OperationalStore
from art_sim.remediation.models import ApprovalDecision
from art_sim.worker.models import SimulationArtifacts, SimulationReview
from art_sim.worker.ports import SimulationDispatcher


class ScenarioCatalog:
    """Allow-list controlled by application composition, never supplied by HTTP clients."""

    def __init__(self, scenario_ids: tuple[str, ...]) -> None:
        """Require a non-empty, unique set of preconfigured simulation scenarios."""
        if not scenario_ids or len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("Scenario catalog must contain unique configured scenarios")
        self._scenario_ids = tuple(sorted(scenario_ids))

    def contains(self, scenario_id: str) -> bool:
        """Return whether a client-selected scenario is operationally configured."""
        return scenario_id in self._scenario_ids

    def list(self) -> tuple[str, ...]:
        """Return public scenario identifiers without implementation internals."""
        return self._scenario_ids


class SimulationService:
    """Coordinate run creation and retrieval without embedding graph or risk logic."""

    def __init__(
        self,
        store: OperationalStore,
        scenarios: ScenarioCatalog,
        workflow_version: str = "v1",
        dispatcher: SimulationDispatcher | None = None,
    ) -> None:
        self._store = store
        self._scenarios = scenarios
        self._workflow_version = workflow_version
        self._dispatcher = dispatcher

    async def create(
        self,
        scenario_id: str,
        actor: str,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> tuple[SimulationRun, bool]:
        """Persist an accepted Shadow scenario; a worker is responsible for actual analysis."""
        if not self._scenarios.contains(scenario_id):
            raise ValueError("Scenario is not configured")
        run = SimulationRun(
            scenario_id=scenario_id,
            graph_version="unresolved",
            workflow_version=self._workflow_version,
            created_by=actor,
            request_id=request_id,
        )
        if idempotency_key is None:
            await self._store.create_run(run)
            if self._dispatcher is not None:
                await self._dispatcher.dispatch(run.run_id)
            return run, True
        persisted, created = await self._store.create_run_idempotent(run, idempotency_key)
        if created and self._dispatcher is not None:
            await self._dispatcher.dispatch(persisted.run_id)
        return persisted, created

    async def create_batch(
        self,
        scenario_ids: tuple[str, ...],
        count: int,
        actor: str,
        idempotency_key: str,
        request_id: str | None = None,
    ) -> tuple[SimulationRun, ...]:
        """Create a bounded set of independently durable, idempotent simulations."""
        if not 1 <= count <= 10:
            raise ValueError("Batch count must be between 1 and 10")
        if not scenario_ids or len(scenario_ids) > 10:
            raise ValueError("Batch requires one to ten configured scenarios")
        if any(not self._scenarios.contains(item) for item in scenario_ids):
            raise ValueError("Batch contains a scenario that is not configured")
        if not 8 <= len(idempotency_key) <= 128:
            raise ValueError("Batch idempotency key is invalid")
        runs: list[SimulationRun] = []
        for index in range(count):
            scenario_id = scenario_ids[index % len(scenario_ids)]
            item_key = sha256(
                f"{idempotency_key}:{scenario_id}:{index}".encode()
            ).hexdigest()
            run, _ = await self.create(
                scenario_id,
                actor,
                item_key,
                request_id,
            )
            runs.append(run)
        return tuple(runs)

    def scenarios(self) -> tuple[str, ...]:
        """Expose only controlled scenario identifiers to the API adapter."""
        return self._scenarios.list()

    async def get(self, run_id: str) -> SimulationRun:
        """Retrieve a run through the repository boundary."""
        return await self._store.get_run(UUID(run_id))

    async def list(self, limit: int, offset: int, status: SimulationRunStatus | None) -> tuple[SimulationRun, ...]:
        """Return a bounded list through the durable repository."""
        return await self._store.list_runs(limit=limit, offset=offset, status=status)

    async def events(self, run_id: UUID) -> tuple[AuditEvent, ...]:
        """Return typed, append-only operational events for an authorized audit read."""
        await self._store.get_run(run_id)
        return await self._store.list_events(run_id)


class ApprovalService:
    """Delegate atomic approval semantics to the existing durable coordinator."""

    def __init__(
        self,
        store: OperationalStore,
        dispatcher: SimulationDispatcher | None = None,
    ) -> None:
        self._store = store
        self._dispatcher = dispatcher

    async def decide(
        self,
        run_id: str,
        decision: ApprovalDecision,
        actor: str,
        reason: str,
    ) -> SimulationRun:
        """Commit exactly one decision through repository compare-and-set."""
        run = await self._store.decide(UUID(run_id), decision, actor, reason)
        if self._dispatcher is not None:
            await self._dispatcher.dispatch(run.run_id)
        return run


class CancellationService:
    """Coordinate durable cancellation CAS and a cooperative worker signal."""

    def __init__(
        self,
        store: OperationalStore,
        dispatcher: SimulationDispatcher | None = None,
    ) -> None:
        self._store = store
        self._dispatcher = dispatcher

    async def cancel(self, run_id: UUID, actor: str) -> SimulationRun:
        """Request cancellation idempotently without terminating a worker process."""
        run = await self._store.request_cancellation(run_id, actor)
        if self._dispatcher is not None:
            await self._dispatcher.cancel(run_id)
        return run


class SimulationResultService:
    """Read immutable worker artifacts only after durable successful completion."""

    def __init__(self, store: OperationalStore) -> None:
        self._store = store

    async def get(self, run_id: UUID) -> SimulationArtifacts:
        """Return final artifacts or a safe conflict for non-successful lifecycles."""
        run = await self._store.get_run(run_id)
        if run.status is not SimulationRunStatus.SUCCEEDED:
            raise ResultNotAvailableError("Simulation result is not available")
        return await self._store.get_result(run_id)


class SimulationReviewService:
    """Expose the immutable pre-approval package without exposing workflow state."""

    def __init__(self, store: OperationalStore) -> None:
        self._store = store

    async def get(self, run_id: UUID) -> SimulationReview:
        """Return review evidence only after the worker persisted the review gate."""
        run = await self._store.get_run(run_id)
        if not run.review_ready:
            raise ResultNotAvailableError("Simulation review is not available")
        return await self._store.get_review(run_id)
