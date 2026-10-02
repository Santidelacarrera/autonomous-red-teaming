"""OpenTelemetry (OTLP) operational telemetry sink — a real production adapter.

Second concrete adapter for a production port. It satisfies ``ExternalOperationalTelemetrySink``
so it can be injected into ``create_production_app``. Metrics map to OTel counters/histograms
from the bounded ``OperationalMetricName`` vocabulary, and traces become OTel spans. High-
cardinality identifiers (run_id/trace_id) are attached to spans, not to metric labels, to
avoid metric-cardinality explosions.

The OpenTelemetry dependencies are optional (``pip install .[telemetry]``); importing this
module requires them. Core domain and API code never import it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import Status, StatusCode

from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.observability.sink import (
    MetricEvent,
    OperationalMetricName,
    TelemetryCapability,
)
from art_sim.observability.telemetry import AgentTelemetry

if TYPE_CHECKING:
    from collections.abc import Mapping

    from opentelemetry.metrics import Counter, Histogram

_INSTRUMENTATION_SCOPE = "art-sim"


def _to_unix_nanos(seconds_epoch: float) -> int:
    """Convert a POSIX timestamp (seconds) to integer nanoseconds for OTel spans."""
    return int(seconds_epoch * 1_000_000_000)


class OtlpTelemetrySink:
    """Export bounded operational metrics and agent traces through OpenTelemetry."""

    deployment_capability: ClassVar[TelemetryCapability] = TelemetryCapability.EXTERNAL

    def __init__(self, meter_provider: MeterProvider, tracer_provider: TracerProvider) -> None:
        """Inject fully-configured OTel providers (deployment owns the exporters)."""
        self._meter_provider = meter_provider
        self._tracer_provider = tracer_provider
        meter = meter_provider.get_meter(_INSTRUMENTATION_SCOPE)
        self._tracer = tracer_provider.get_tracer(_INSTRUMENTATION_SCOPE)
        self._counters: dict[OperationalMetricName, Counter] = {}
        self._histograms: dict[OperationalMetricName, Histogram] = {}
        for name in OperationalMetricName:
            if name.value.endswith("_seconds"):
                self._histograms[name] = meter.create_histogram(name.value, unit="s")
            else:
                self._counters[name] = meter.create_counter(name.value)

    @classmethod
    def from_endpoint(
        cls, endpoint: str, *, headers: Mapping[str, str] | None = None
    ) -> OtlpTelemetrySink:
        """Build providers wired to an OTLP/HTTP collector owned by the deployment."""
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        base = endpoint.rstrip("/")
        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=f"{base}/v1/metrics", headers=dict(headers or {}))
        )
        meter_provider = MeterProvider(metric_readers=[reader])
        tracer_provider = TracerProvider()
        tracer_provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=f"{base}/v1/traces", headers=dict(headers or {}))
            )
        )
        return cls(meter_provider, tracer_provider)

    async def emit_metric(self, event: MetricEvent) -> None:
        """Record one bounded metric as an OTel counter add or histogram observation."""
        try:
            histogram = self._histograms.get(event.name)
            if histogram is not None:
                histogram.record(event.value)
            else:
                self._counters[event.name].add(event.value)
        except Exception as error:  # adapter boundary: map any backend fault to a safe domain error
            raise DependencyUnavailableError("Telemetry backend is unavailable") from error

    async def emit_trace(self, event: AgentTelemetry) -> None:
        """Export one agent/node execution as a correlated OTel span."""
        try:
            span = self._tracer.start_span(
                event.node_name,
                start_time=_to_unix_nanos(event.started_at.timestamp()),
                attributes={
                    "art_sim.component": event.agent_name,
                    "art_sim.run_id": str(event.run_id),
                    "art_sim.trace_id": str(event.trace_id),
                    "art_sim.span_id": str(event.span_id),
                    "art_sim.status": event.status,
                    "art_sim.duration_ms": event.duration_ms,
                    "art_sim.retry_count": event.retry_count,
                },
            )
            ok = event.status == "succeeded"
            span.set_status(Status(StatusCode.OK if ok else StatusCode.ERROR))
            if event.error is not None:
                span.set_attribute("art_sim.error", event.error)
            span.end(end_time=_to_unix_nanos(event.ended_at.timestamp()))
        except Exception as error:  # adapter boundary: map any backend fault to a safe domain error
            raise DependencyUnavailableError("Telemetry backend is unavailable") from error

    async def health_check(self) -> None:
        """Flush both pipelines so readiness reflects real exporter availability."""
        try:
            self._meter_provider.force_flush()
            self._tracer_provider.force_flush()
        except Exception as error:  # adapter boundary: map any backend fault to a safe domain error
            raise DependencyUnavailableError("Telemetry backend is unavailable") from error

    async def close(self) -> None:
        """Flush and shut down both OTel providers during graceful shutdown."""
        self._meter_provider.shutdown()
        self._tracer_provider.shutdown()
