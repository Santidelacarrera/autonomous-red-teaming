"""Tests for the OTLP telemetry adapter using in-memory OpenTelemetry exporters, so the
real metric/span pipeline is exercised without a collector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from art_sim.adapters.otlp_telemetry import OtlpTelemetrySink
from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.observability.sink import MetricEvent, OperationalMetricName, TelemetryCapability
from art_sim.observability.telemetry import AgentTelemetry


@pytest.fixture
def pipeline() -> tuple[OtlpTelemetrySink, InMemoryMetricReader, InMemorySpanExporter]:
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    sink = OtlpTelemetrySink(meter_provider, tracer_provider)
    return sink, reader, span_exporter


def _metric_points(reader: InMemoryMetricReader, name: str) -> list[object]:
    data = reader.get_metrics_data()
    points: list[object] = []
    for resource_metric in getattr(data, "resource_metrics", []):
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                if metric.name == name:
                    points.extend(metric.data.data_points)
    return points


def _trace() -> AgentTelemetry:
    start = datetime.now(UTC)
    return AgentTelemetry(
        run_id=uuid4(),
        trace_id=uuid4(),
        span_id=uuid4(),
        agent_name="recon",
        node_name="observe_topology",
        started_at=start,
        ended_at=start + timedelta(milliseconds=12),
        duration_ms=12.0,
        status="succeeded",
        input_size=3,
        output_size=5,
    )


def _metric(name: OperationalMetricName, value: float) -> MetricEvent:
    return MetricEvent(name=name, value=value, run_id=uuid4(), trace_id=uuid4())


async def test_adapter_declares_external_capability() -> None:
    assert OtlpTelemetrySink.deployment_capability is TelemetryCapability.EXTERNAL


async def test_counter_metric_is_exported(
    pipeline: tuple[OtlpTelemetrySink, InMemoryMetricReader, InMemorySpanExporter],
) -> None:
    sink, reader, _ = pipeline
    await sink.emit_metric(_metric(OperationalMetricName.SIMULATIONS_STARTED, 1))
    await sink.emit_metric(_metric(OperationalMetricName.SIMULATIONS_STARTED, 2))
    points = _metric_points(reader, "simulations_started_total")
    assert points
    assert sum(p.value for p in points) == 3  # type: ignore[attr-defined]


async def test_histogram_metric_is_exported(
    pipeline: tuple[OtlpTelemetrySink, InMemoryMetricReader, InMemorySpanExporter],
) -> None:
    sink, reader, _ = pipeline
    await sink.emit_metric(_metric(OperationalMetricName.SIMULATION_DURATION, 1.5))
    points = _metric_points(reader, "simulation_duration_seconds")
    assert points
    assert points[0].count == 1  # type: ignore[attr-defined]
    assert points[0].sum == pytest.approx(1.5)  # type: ignore[attr-defined]


async def test_trace_is_exported_as_span(
    pipeline: tuple[OtlpTelemetrySink, InMemoryMetricReader, InMemorySpanExporter],
) -> None:
    sink, _, span_exporter = pipeline
    event = _trace()
    await sink.emit_trace(event)
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "observe_topology"
    assert span.attributes is not None
    assert span.attributes["art_sim.component"] == "recon"
    assert span.attributes["art_sim.run_id"] == str(event.run_id)


async def test_failed_trace_sets_error_status(
    pipeline: tuple[OtlpTelemetrySink, InMemoryMetricReader, InMemorySpanExporter],
) -> None:
    sink, _, span_exporter = pipeline
    start = datetime.now(UTC)
    event = AgentTelemetry(
        run_id=uuid4(),
        trace_id=uuid4(),
        span_id=uuid4(),
        agent_name="planner",
        node_name="plan",
        started_at=start,
        ended_at=start + timedelta(milliseconds=5),
        duration_ms=5.0,
        status="failed",
        input_size=1,
        output_size=0,
        error="boom",
    )
    await sink.emit_trace(event)
    span = span_exporter.get_finished_spans()[0]
    assert span.status.status_code.name == "ERROR"
    assert span.attributes is not None
    assert span.attributes["art_sim.error"] == "boom"


async def test_health_check_flushes_without_error(
    pipeline: tuple[OtlpTelemetrySink, InMemoryMetricReader, InMemorySpanExporter],
) -> None:
    sink, _, _ = pipeline
    await sink.health_check()
    await sink.close()


async def test_backend_errors_map_to_dependency_unavailable(
    pipeline: tuple[OtlpTelemetrySink, InMemoryMetricReader, InMemorySpanExporter],
) -> None:
    sink, _, _ = pipeline

    class _Boom:
        def add(self, *_: object, **__: object) -> None:
            raise RuntimeError("exporter down")

    sink._counters[OperationalMetricName.SIMULATIONS_STARTED] = _Boom()  # type: ignore[assignment]
    with pytest.raises(DependencyUnavailableError):
        await sink.emit_metric(_metric(OperationalMetricName.SIMULATIONS_STARTED, 1))
