"""OTLP telemetry over a real socket: data actually reaches a collector, and readiness is honest.

A tiny HTTP server stands in for an OpenTelemetry Collector's OTLP/HTTP receiver. Unlike the
in-memory exporter tests, this exercises the real exporters, protobuf encoding, HTTP transport
and the readiness probe — the path a production deployment depends on.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from art_sim.adapters.otlp_telemetry import OtlpTelemetrySink
from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.observability.sink import MetricEvent, OperationalMetricName
from art_sim.observability.telemetry import AgentTelemetry


class _Collector:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bytes]] = []
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                collector.requests.append((self.path, self.headers.get("Content-Type", ""), body))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.end_headers()

            def do_GET(self) -> None:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"Server available"}')

            def log_message(self, *_: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def collector() -> Iterator[_Collector]:
    server = _Collector()
    yield server
    server.stop()


def _metric(name: OperationalMetricName, value: float) -> MetricEvent:
    return MetricEvent(name=name, value=value, run_id=uuid4(), trace_id=uuid4())


def _trace(run_id: object) -> AgentTelemetry:
    start = datetime.now(UTC)
    return AgentTelemetry(
        run_id=run_id,  # type: ignore[arg-type]
        trace_id=uuid4(),
        span_id=uuid4(),
        agent_name="recon",
        node_name="observe_topology",
        started_at=start,
        ended_at=start + timedelta(milliseconds=7),
        duration_ms=7.0,
        status="succeeded",
        input_size=1,
        output_size=2,
    )


async def test_metrics_and_traces_reach_the_collector_as_valid_otlp(collector: _Collector) -> None:
    sink = OtlpTelemetrySink.from_endpoint(collector.endpoint)
    run_id = uuid4()
    await sink.emit_metric(_metric(OperationalMetricName.SIMULATIONS_STARTED, 3))
    await sink.emit_trace(_trace(run_id))
    await sink.health_check()  # probes the collector, then force-flushes both pipelines
    await sink.close()

    paths = {path for path, _, _ in collector.requests}
    assert {"/v1/metrics", "/v1/traces"} <= paths
    assert all(ctype == "application/x-protobuf" for _, ctype, _ in collector.requests)

    metrics = ExportMetricsServiceRequest()
    traces = ExportTraceServiceRequest()
    for path, _, body in collector.requests:
        if path == "/v1/metrics":
            metrics.ParseFromString(body)
        elif path == "/v1/traces":
            traces.ParseFromString(body)
    metric_names = {
        metric.name
        for resource in metrics.resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
    }
    assert "simulations_started_total" in metric_names
    spans = [
        span
        for resource in traces.resource_spans
        for scope in resource.scope_spans
        for span in scope.spans
    ]
    assert [span.name for span in spans] == ["observe_topology"]
    attributes = {attribute.key: attribute.value.string_value for attribute in spans[0].attributes}
    assert attributes["art_sim.run_id"] == str(run_id)
    assert attributes["art_sim.component"] == "recon"


async def test_readiness_passes_when_the_collector_is_reachable(collector: _Collector) -> None:
    sink = OtlpTelemetrySink.from_endpoint(collector.endpoint)
    await sink.health_check()
    await sink.close()


async def test_readiness_uses_the_collector_health_endpoint_when_configured(
    collector: _Collector,
) -> None:
    sink = OtlpTelemetrySink.from_endpoint(collector.endpoint, health_url=f"{collector.endpoint}/health")
    await sink.health_check()
    await sink.close()


async def test_readiness_fails_when_the_collector_is_down() -> None:
    """Regression: force_flush alone reports success while every export is being dropped."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    sink = OtlpTelemetrySink.from_endpoint(f"http://127.0.0.1:{closed_port}")
    await sink.emit_metric(_metric(OperationalMetricName.SIMULATIONS_STARTED, 1))
    with pytest.raises(DependencyUnavailableError):
        await sink.health_check()
    await sink.close()


async def test_readiness_fails_when_the_collector_stops_after_start(collector: _Collector) -> None:
    sink = OtlpTelemetrySink.from_endpoint(collector.endpoint)
    await sink.health_check()
    collector.stop()
    with pytest.raises(DependencyUnavailableError):
        await sink.health_check()
    await sink.close()


def test_endpoint_without_a_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="host"):
        OtlpTelemetrySink.from_endpoint("not-a-url")
