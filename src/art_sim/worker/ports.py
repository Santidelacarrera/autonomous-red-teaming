"""Provider-neutral dispatcher, scenario, and workflow execution ports."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Protocol
from uuid import UUID

from art_sim.worker.jobs import CancellationReceipt, DispatchReceipt, SimulationJobV1
from art_sim.worker.models import SimulationScenario


class DispatcherScope(StrEnum):
    """Delivery scope declared by a dispatcher adapter."""

    PROCESS = "process"
    DISTRIBUTED = "distributed"


class SimulationDispatcher(Protocol):
    """Submit an already persisted run for asynchronous internal processing."""

    deployment_scope: ClassVar[DispatcherScope]

    async def dispatch(self, run_id: UUID) -> DispatchReceipt: ...

    async def cancel(self, run_id: UUID) -> CancellationReceipt: ...


class DistributedSimulationDispatcher(SimulationDispatcher, Protocol):
    """Port for a durable external queue/worker trigger supplied by production."""


class BrokerTransport(Protocol):
    """Minimal durable broker publishing boundary supplied by a deployment adapter."""

    async def publish(self, job: SimulationJobV1, deduplication_key: str) -> bool:
        """Publish once logically; return false when the broker reports a duplicate."""

    async def publish_cancellation(self, run_id: UUID, correlation_id: str) -> bool:
        """Publish a cooperative cancellation signal without terminating a process."""


class BrokerJobDelivery(Protocol):
    """One externally delivered payload with explicit settlement operations."""

    payload: bytes

    async def acknowledge(self) -> None: ...

    async def retry_later(self) -> None: ...

    async def dead_letter(self, reason_code: str) -> None: ...


class BrokerJobConsumer(Protocol):
    """External-worker consumer port; deployments own the concrete broker loop."""

    async def receive(self) -> BrokerJobDelivery | None: ...

    async def close(self) -> None: ...


class ScenarioRepository(Protocol):
    """Resolve only operator-configured, immutable Shadow scenarios."""

    async def get(self, scenario_id: str) -> SimulationScenario: ...


class ScenarioAllowList(Protocol):
    """Minimal catalog policy consumed by the worker without depending on FastAPI."""

    def contains(self, scenario_id: str) -> bool: ...
