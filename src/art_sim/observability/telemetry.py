"""In-memory structured telemetry with no external service dependency."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from time import perf_counter
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from art_sim.observability.sink import TelemetrySink


class AgentTelemetry(BaseModel):
    """Auditable agent/node execution measurement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    trace_id: UUID
    span_id: UUID
    agent_name: str = Field(min_length=1, max_length=128)
    node_name: str = Field(min_length=1, max_length=128)
    started_at: datetime
    ended_at: datetime
    duration_ms: float = Field(ge=0.0)
    status: str = Field(pattern=r"^(succeeded|failed|rejected|blocked)$")
    input_size: int = Field(ge=0)
    output_size: int = Field(ge=0)
    error: str | None = Field(default=None, max_length=256)
    retry_count: int = Field(default=0, ge=0)


class TraceSpan(BaseModel):
    """One trace span that can be exported to OpenTelemetry later."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_id: UUID
    span_id: UUID
    parent_span_id: UUID | None = None
    name: str = Field(min_length=1, max_length=128)
    started_at: datetime
    ended_at: datetime
    duration_ms: float = Field(ge=0.0)
    status: str = Field(pattern=r"^(succeeded|failed)$")


class MetricsRegistry:
    """Minimal aggregate counters and duration series for a single process run."""

    def __init__(self) -> None:
        """Create an empty registry without global mutable state."""
        self._counters: dict[str, int] = {}
        self._durations_ms: dict[str, list[float]] = {}

    def increment(self, name: str, amount: int = 1) -> None:
        """Increase an explicit counter by a non-negative integer."""
        if amount < 0:
            raise ValueError("metric amount must not be negative")
        self._counters[name] = self._counters.get(name, 0) + amount

    def observe_duration(self, name: str, duration_ms: float) -> None:
        """Record a non-negative duration for later aggregation."""
        if duration_ms < 0:
            raise ValueError("duration must not be negative")
        self._durations_ms.setdefault(name, []).append(duration_ms)

    def snapshot(self) -> dict[str, float | int]:
        """Return immutable-value metrics including averages where samples exist."""
        result: dict[str, float | int] = dict(self._counters)
        for name, durations in self._durations_ms.items():
            result[f"average_{name}"] = round(sum(durations) / len(durations), 2) if durations else 0.0
        return result


class Tracer:
    """Collect structured spans and agent telemetry for one simulation run."""

    def __init__(
        self, run_id: UUID | None = None, metrics: MetricsRegistry | None = None, sink: TelemetrySink | None = None
    ) -> None:
        """Inject an optional run identity and metrics registry."""
        self.run_id = run_id or uuid4()
        self.trace_id = uuid4()
        self.metrics = metrics or MetricsRegistry()
        self._sink = sink
        self.spans: list[TraceSpan] = []
        self.agent_events: list[AgentTelemetry] = []

    @contextmanager
    def span(self, name: str, *, parent_span_id: UUID | None = None) -> Iterator[UUID]:
        """Record a trace span for success or failure without suppressing exceptions."""
        span_id = uuid4()
        started_at = datetime.now(UTC)
        started = perf_counter()
        status = "succeeded"
        try:
            yield span_id
        except Exception:
            status = "failed"
            raise
        finally:
            duration_ms = (perf_counter() - started) * 1000.0
            self.spans.append(
                TraceSpan(
                    trace_id=self.trace_id,
                    span_id=span_id,
                    parent_span_id=parent_span_id,
                    name=name,
                    started_at=started_at,
                    ended_at=datetime.now(UTC),
                    duration_ms=duration_ms,
                    status=status,
                )
            )
            self.metrics.observe_duration("agent_duration_ms", duration_ms)

    def record_agent_event(
        self,
        *,
        agent_name: str,
        node_name: str,
        started_at: datetime,
        input_size: int,
        output_size: int,
        status: str,
        error: str | None = None,
        retry_count: int = 0,
    ) -> AgentTelemetry:
        """Append an agent event and update success/failure counters."""
        ended_at = datetime.now(UTC)
        event = AgentTelemetry(
            run_id=self.run_id,
            trace_id=self.trace_id,
            span_id=uuid4(),
            agent_name=agent_name,
            node_name=node_name,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=max(0.0, (ended_at - started_at).total_seconds() * 1000.0),
            status=status,
            input_size=input_size,
            output_size=output_size,
            error=error,
            retry_count=retry_count,
        )
        self.agent_events.append(event)
        if self._sink is not None:
            self._sink.emit(event)
        self.metrics.increment("agent_executions_successful" if status == "succeeded" else "agent_executions_failed")
        return event
