"""Thin application services coordinating durable operational contracts for HTTP."""

from __future__ import annotations

from art_sim.platform.models import SimulationRun, SimulationRunStatus
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.remediation.models import ApprovalDecision


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
        self, store: SqliteOperationalStore, scenarios: ScenarioCatalog, workflow_version: str = "v1"
    ) -> None:
        self._store = store
        self._scenarios = scenarios
        self._workflow_version = workflow_version

    async def create(
        self, scenario_id: str, actor: str, idempotency_key: str | None = None
    ) -> tuple[SimulationRun, bool]:
        """Persist an accepted Shadow scenario; a worker is responsible for actual analysis."""
        if not self._scenarios.contains(scenario_id):
            raise ValueError("Scenario is not configured")
        run = SimulationRun(
            scenario_id=scenario_id,
            graph_version="unresolved",
            workflow_version=self._workflow_version,
            created_by=actor,
        )
        if idempotency_key is None:
            await self._store.create_run(run)
            return run, True
        return await self._store.create_run_idempotent(run, idempotency_key)

    def scenarios(self) -> tuple[str, ...]:
        """Expose only controlled scenario identifiers to the API adapter."""
        return self._scenarios.list()

    async def get(self, run_id: str) -> SimulationRun:
        """Retrieve a run through the repository boundary."""
        from uuid import UUID

        return await self._store.get_run(UUID(run_id))

    async def list(self, limit: int, offset: int, status: SimulationRunStatus | None) -> tuple[SimulationRun, ...]:
        """Return a bounded list through the durable repository."""
        return await self._store.list_runs(limit=limit, offset=offset, status=status)


class ApprovalService:
    """Delegate atomic approval semantics to the existing durable coordinator."""

    def __init__(self, store: SqliteOperationalStore) -> None:
        self._store = store

    async def decide(self, run_id: str, decision: ApprovalDecision, actor: str) -> SimulationRun:
        """Commit exactly one decision through repository compare-and-set."""
        from uuid import UUID

        return await self._store.decide(UUID(run_id), decision, actor)
