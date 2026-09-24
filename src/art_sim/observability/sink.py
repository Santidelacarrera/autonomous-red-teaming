"""Safe telemetry-sink abstraction for future external observability adapters."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from art_sim.observability.telemetry import AgentTelemetry


class TelemetrySink(Protocol):
    """Accept a typed telemetry event without requiring a specific backend."""

    def emit(self, event: AgentTelemetry) -> None:
        """Write one safe, correlated telemetry event."""


class StructuredLoggingTelemetrySink:
    """Emit JSON logs from typed fields only; no raw state or secret material is accepted."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Use an injected application logger or this module's logger."""
        self._logger = logger or logging.getLogger(__name__)

    def emit(self, event: AgentTelemetry) -> None:
        """Write a one-line structured event correlated by run and trace IDs."""
        self._logger.info(
            json.dumps(
                {
                    "event": "agent.execution",
                    "run_id": str(event.run_id),
                    "trace_id": str(event.trace_id),
                    "component": event.agent_name,
                    "node": event.node_name,
                    "status": event.status,
                    "duration_ms": event.duration_ms,
                }, separators=(",", ":")
            )
        )


class TelemetryCapability(StrEnum):
    """Delivery scope declared by an operational telemetry adapter."""

    PROCESS = "process"
    EXTERNAL = "external"


class MetricEvent(BaseModel):
    """Safe correlated metric event without arbitrary labels or payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^simulation_[a-z_]+(?:_total|_seconds)$")
    value: float = Field(ge=0.0)
    run_id: UUID
    trace_id: UUID
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OperationalTelemetrySink(Protocol):
    """Asynchronous provider-neutral port for metrics and trace events."""

    deployment_capability: ClassVar[TelemetryCapability]

    async def emit_metric(self, event: MetricEvent) -> None: ...

    async def emit_trace(self, event: AgentTelemetry) -> None: ...


class InMemoryOperationalTelemetrySink:
    """Bounded development collector; production must inject an external adapter."""

    deployment_capability: ClassVar[TelemetryCapability] = TelemetryCapability.PROCESS

    def __init__(self, capacity: int = 2000) -> None:
        if capacity < 1:
            raise ValueError("Telemetry capacity must be positive")
        self._capacity = capacity
        self.metrics: list[MetricEvent] = []
        self.traces: list[AgentTelemetry] = []

    async def emit_metric(self, event: MetricEvent) -> None:
        """Append one typed metric and retain bounded recent history."""
        self.metrics.append(event)
        if len(self.metrics) > self._capacity:
            del self.metrics[: len(self.metrics) - self._capacity]

    async def emit_trace(self, event: AgentTelemetry) -> None:
        """Append one typed trace event and retain bounded recent history."""
        self.traces.append(event)
        if len(self.traces) > self._capacity:
            del self.traces[: len(self.traces) - self._capacity]


class ExternalOperationalTelemetrySink(OperationalTelemetrySink, Protocol):
    """Production port for OpenTelemetry, Prometheus, or an equivalent backend."""
