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


class OperationalMetricName(StrEnum):
    """Bounded metric vocabulary; arbitrary labels and payloads are not accepted."""

    SIMULATIONS_STARTED = "simulations_started_total"
    SIMULATIONS_SUCCEEDED = "simulations_succeeded_total"
    SIMULATIONS_FAILED = "simulations_failed_total"
    SIMULATIONS_CANCELLED = "simulations_cancelled_total"
    SIMULATIONS_RECOVERED = "simulations_recovered_total"
    SIMULATION_DURATION = "simulation_duration_seconds"
    SIMULATION_STAGE_DURATION = "simulation_stage_duration_seconds"
    LEASE_EXPIRATIONS = "lease_expirations_total"
    FENCING_REJECTIONS = "fencing_rejections_total"
    APPROVAL_LATENCY = "approval_latency_seconds"
    RESULT_PERSISTENCE_FAILURES = "result_persistence_failures_total"
    BROKER_FAILURES = "broker_failures_total"
    DATABASE_FAILURES = "database_failures_total"
    POISON_JOBS = "poison_jobs_total"
    RETRY_COUNT = "retry_count_total"
    ACTIVE_WORKERS = "active_workers_total"
    TELEMETRY_DELIVERY_FAILURES = "telemetry_delivery_failures_total"
    SIMULATION_APPROVAL = "simulation_approval_total"
    SIMULATION_REJECTED = "simulation_rejected_total"


class MetricEvent(BaseModel):
    """Safe correlated metric event without arbitrary labels or payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: OperationalMetricName
    value: float = Field(ge=0.0)
    run_id: UUID
    trace_id: UUID
    request_id: str | None = Field(default=None, max_length=64)
    worker_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    fencing_token: int | None = Field(default=None, ge=1)
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

    async def health_check(self) -> None:
        """Verify bounded export availability without emitting sensitive state."""

    async def close(self) -> None:
        """Flush pending telemetry and release exporter resources."""
