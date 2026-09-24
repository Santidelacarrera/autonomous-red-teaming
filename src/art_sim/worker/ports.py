"""Provider-neutral dispatcher, scenario, and workflow execution ports."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Protocol
from uuid import UUID

from art_sim.worker.broker import BrokerHealth, BrokerProvider
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

    async def health_check(self) -> None: ...

    async def close(self) -> None: ...


class BrokerTransport(Protocol):
    """Durable broker publishing boundary supplied by a deployment adapter."""

    provider: ClassVar[BrokerProvider]

    async def publish(self, job: SimulationJobV1, deduplication_key: str) -> bool:
        """Publish once logically; return false when the broker reports a duplicate."""

    async def publish_cancellation(self, run_id: UUID, correlation_id: str) -> bool:
        """Publish a cooperative cancellation signal without terminating a process."""

    async def health_check(self) -> BrokerHealth:
        """Verify connectivity without publishing a job or disclosing configuration."""

    async def close(self) -> None:
        """Stop accepting publishes and release connections within a bounded grace period."""


class BrokerJobDelivery(Protocol):
    """One externally delivered payload with explicit settlement operations."""

    payload: bytes
    delivery_id: str
    correlation_id: str
    delivery_attempt: int

    async def acknowledge(self) -> None: ...

    async def retry_later(self) -> None: ...

    async def negative_acknowledge(self, *, requeue: bool) -> None: ...

    async def extend_visibility(self, timeout_seconds: int) -> None: ...

    async def dead_letter(self, reason_code: str) -> None: ...


class BrokerJobConsumer(Protocol):
    """External-worker consumer port; deployments own the concrete broker loop."""

    async def receive(self, *, timeout_seconds: float = 5.0) -> BrokerJobDelivery | None: ...

    async def pause(self) -> None: ...

    async def resume(self) -> None: ...

    async def health_check(self) -> BrokerHealth: ...

    async def close(self) -> None: ...


class ScenarioRepository(Protocol):
    """Resolve only operator-configured, immutable Shadow scenarios."""

    async def get(self, scenario_id: str) -> SimulationScenario: ...


class ScenarioAllowList(Protocol):
    """Minimal catalog policy consumed by the worker without depending on FastAPI."""

    def contains(self, scenario_id: str) -> bool: ...
