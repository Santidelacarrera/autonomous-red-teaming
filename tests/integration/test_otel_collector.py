"""Telemetry delivered to a real OpenTelemetry Collector, using the repository's own config.

Starts the Collector image with ``deploy/otel-collector.yaml`` (OTLP/HTTP receiver, debug
exporter), sends metrics and a span through ``OtlpTelemetrySink``, and reads the Collector's
own log to prove it *ingested* them. Then stops the Collector and proves readiness turns red.

Skipped, visibly, when Docker or the image is unavailable. Override the image with
``ART_OTEL_IMAGE`` (e.g. ``mirror.gcr.io/otel/opentelemetry-collector:0.110.0`` when Docker Hub
rate-limits anonymous pulls). This verifies the Collector hop; it does not verify any vendor
backend behind it (see docs/integrations.md).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from art_sim.adapters.otlp_telemetry import OtlpTelemetrySink
from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.observability.sink import MetricEvent, OperationalMetricName
from art_sim.observability.telemetry import AgentTelemetry

IMAGE = os.getenv("ART_OTEL_IMAGE", "otel/opentelemetry-collector:0.110.0")
CONFIG = Path(__file__).resolve().parents[2] / "deploy" / "otel-collector.yaml"


def _docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def collector() -> Iterator[tuple[str, str]]:
    if shutil.which("docker") is None or _docker("info").returncode != 0:
        pytest.skip("Docker daemon is not available")
    if _docker("image", "inspect", IMAGE).returncode != 0 and _docker("pull", IMAGE, timeout=300).returncode != 0:
        pytest.skip(f"cannot pull {IMAGE} (offline or rate-limited; set ART_OTEL_IMAGE)")
    name = f"art-sim-otel-{uuid4().hex[:8]}"
    port = _free_port()
    started = _docker(
        "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:4318",
        "-v", f"{CONFIG}:/etc/otelcol/config.yaml:ro", IMAGE, "--config=/etc/otelcol/config.yaml",
    )
    if started.returncode != 0:
        pytest.skip(f"could not start the collector: {started.stderr.strip()[:200]}")
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.5)
        else:
            pytest.skip("collector did not open its OTLP port in time")
        yield name, f"http://127.0.0.1:{port}"
    finally:
        _docker("rm", "-f", name)


def _logs(name: str) -> str:
    result = _docker("logs", name)
    return result.stdout + result.stderr


async def test_collector_ingests_metrics_and_spans_from_the_sink(collector: tuple[str, str]) -> None:
    name, endpoint = collector
    sink = OtlpTelemetrySink.from_endpoint(endpoint)
    run_id = uuid4()
    start = datetime.now(UTC)
    await sink.emit_metric(
        MetricEvent(name=OperationalMetricName.SIMULATIONS_STARTED, value=2, run_id=run_id, trace_id=uuid4())
    )
    await sink.emit_trace(
        AgentTelemetry(
            run_id=run_id, trace_id=uuid4(), span_id=uuid4(), agent_name="recon", node_name="observe_topology",
            started_at=start, ended_at=start + timedelta(milliseconds=9), duration_ms=9.0, status="succeeded",
            input_size=1, output_size=1,
        )
    )
    await sink.health_check()
    await sink.close()

    deadline = time.monotonic() + 20
    logs = ""
    while time.monotonic() < deadline:
        logs = _logs(name)
        if "simulations_started_total" in logs and "observe_topology" in logs:
            break
        await asyncio.sleep(0.5)
    assert "simulations_started_total" in logs, logs[-800:]
    assert "observe_topology" in logs, logs[-800:]
    assert str(run_id) in logs  # span attribute made it through the real pipeline


async def test_readiness_goes_red_when_the_collector_stops(collector: tuple[str, str]) -> None:
    name, endpoint = collector
    sink = OtlpTelemetrySink.from_endpoint(endpoint)
    await sink.health_check()
    assert _docker("stop", "-t", "2", name).returncode == 0
    with pytest.raises(DependencyUnavailableError):
        await sink.health_check()
    await sink.close()
