"""Central transition policy for the durable operational simulation lifecycle."""

from __future__ import annotations

from typing import ClassVar

from art_sim.domain.exceptions import WorkerStateError
from art_sim.platform.models import SimulationRunStatus


class SimulationRunStateMachine:
    """Validate every worker-owned transition and prevent terminal resurrection."""

    TERMINAL: ClassVar[frozenset[SimulationRunStatus]] = frozenset(
        {
            SimulationRunStatus.SUCCEEDED,
            SimulationRunStatus.COMPLETED,
            SimulationRunStatus.FAILED,
            SimulationRunStatus.REJECTED,
            SimulationRunStatus.CANCELLED,
        }
    )
    _ALLOWED: ClassVar[dict[SimulationRunStatus, frozenset[SimulationRunStatus]]] = {
        SimulationRunStatus.CREATED: frozenset(
            {
                SimulationRunStatus.RUNNING,
                SimulationRunStatus.FAILED,
                SimulationRunStatus.CANCELLED,
            }
        ),
        SimulationRunStatus.RUNNING: frozenset(
            {
                SimulationRunStatus.WAITING_APPROVAL,
                SimulationRunStatus.SUCCEEDED,
                SimulationRunStatus.FAILED,
                SimulationRunStatus.REJECTED,
                SimulationRunStatus.CANCELLED,
            }
        ),
        SimulationRunStatus.WAITING_APPROVAL: frozenset(
            {
                SimulationRunStatus.RESUMING,
                SimulationRunStatus.REJECTED,
                SimulationRunStatus.FAILED,
                SimulationRunStatus.CANCELLED,
            }
        ),
        SimulationRunStatus.RESUMING: frozenset(
            {
                SimulationRunStatus.RUNNING,
                SimulationRunStatus.SUCCEEDED,
                SimulationRunStatus.FAILED,
                SimulationRunStatus.REJECTED,
                SimulationRunStatus.CANCELLED,
            }
        ),
        SimulationRunStatus.SUCCEEDED: frozenset(),
        SimulationRunStatus.COMPLETED: frozenset(),
        SimulationRunStatus.FAILED: frozenset(),
        SimulationRunStatus.REJECTED: frozenset(),
        SimulationRunStatus.CANCELLED: frozenset(),
    }

    @classmethod
    def require(cls, source: SimulationRunStatus, target: SimulationRunStatus) -> None:
        """Raise a safe domain error unless the transition is explicitly allowed."""
        if target not in cls._ALLOWED[source]:
            raise WorkerStateError(
                f"Invalid simulation lifecycle transition: {source.value} -> {target.value}"
            )
