"""Operational configuration, health, and telemetry-sink regression tests."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from art_sim.domain.exceptions import ConfigurationError
from art_sim.observability.sink import StructuredLoggingTelemetrySink
from art_sim.observability.telemetry import AgentTelemetry, Tracer
from art_sim.platform.config import OperationalSettings, RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.security.secrets import EnvironmentSecretProvider


def test_operational_settings_resolve_secret_or_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment profile settings reject an absent or undersized approval secret."""
    settings = OperationalSettings(environment=RuntimeEnvironment.STAGING)
    provider = EnvironmentSecretProvider()
    monkeypatch.delenv("ART_SIM_APPROVAL_SECRET", raising=False)
    with pytest.raises(ConfigurationError):
        settings.approval_secret(provider)
    monkeypatch.setenv("ART_SIM_APPROVAL_SECRET", "too-short")
    with pytest.raises(ConfigurationError, match="32"):
        settings.approval_secret(provider)
    monkeypatch.setenv("ART_SIM_APPROVAL_SECRET", "a" * 32)
    assert settings.approval_secret(provider) == b"a" * 32


async def test_health_and_readiness_do_not_expose_failure_details() -> None:
    """A failed dependency turns readiness off while liveness remains safe and minimal."""
    async def unavailable() -> None:
        raise OSError("database password is secret")

    service = HealthService({"operations_store": unavailable})
    assert (await service.health()).model_dump() == {"status": "ok", "checks": {"process": "ok"}}
    assert (await service.readiness()).model_dump() == {
        "status": "not_ready",
        "checks": {"operations_store": "unavailable"},
    }


def test_structured_telemetry_sink_logs_only_safe_correlation_fields(caplog: pytest.LogCaptureFixture) -> None:
    """The sink does not serialize an event error field that could carry sensitive content."""
    logger = logging.getLogger("test.operational.telemetry")
    sink = StructuredLoggingTelemetrySink(logger)
    now = datetime.now(UTC)
    event = AgentTelemetry(
        run_id=uuid4(), trace_id=uuid4(), span_id=uuid4(), agent_name="approval", node_name="decision",
        started_at=now, ended_at=now, duration_ms=0.0, status="failed", input_size=0, output_size=0,
        error="password=not-for-output",
    )
    with caplog.at_level(logging.INFO, logger="test.operational.telemetry"):
        sink.emit(event)
    assert "password" not in caplog.text
    assert '"run_id"' in caplog.text


def test_tracer_forwards_event_to_injected_sink() -> None:
    """Correlation-preserving telemetry remains injectable instead of globally configured."""
    class RecordingSink:
        def __init__(self) -> None:
            self.events: list[AgentTelemetry] = []

        def emit(self, event: AgentTelemetry) -> None:
            self.events.append(event)

    sink = RecordingSink()
    tracer = Tracer(sink=sink)
    tracer.record_agent_event(agent_name="risk", node_name="assess", started_at=datetime.now(UTC), input_size=1, output_size=1, status="succeeded")
    assert sink.events[0].run_id == tracer.run_id
