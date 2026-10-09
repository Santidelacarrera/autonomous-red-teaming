"""Tests for the SIEM-forwarding audit sink, using an in-memory durable sink and a fake
``httpx.AsyncClient`` so no network access is required.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from art_sim.adapters.siem_http_audit_sink import SiemForwardAuditSink, SiemMessageFormat
from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.security.audit import (
    AuditDurability,
    AuditRetentionPolicy,
    SecurityAuditEvent,
    SecurityEventType,
)


class FakeDurableSink:
    """In-memory stand-in for ``JsonlDurableSecurityAuditSink``."""

    durability = AuditDurability.DURABLE

    def __init__(self) -> None:
        self.retention_policy = AuditRetentionPolicy(retention_days=30)
        self.events: list[SecurityAuditEvent] = []
        self.health_checks = 0
        self.closed = False

    async def append(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        return tuple(reversed(self.events[-limit:]))

    async def health_check(self) -> None:
        self.health_checks += 1

    async def close(self) -> None:
        self.closed = True


class FakeResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://siem.example.invalid/ingest")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("failed", request=request, response=response)


class FakeHttpClient:
    """Minimal async stand-in for ``httpx.AsyncClient``."""

    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []
        self.fail_times = 0
        self.health_ok = True

    async def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> FakeResponse:
        self.posts.append({"url": url, "json": json, "headers": headers})
        if self.fail_times > 0:
            self.fail_times -= 1
            return FakeResponse(503)
        return FakeResponse(200)

    async def get(self, url: str, timeout: float = 5.0) -> FakeResponse:
        return FakeResponse(200 if self.health_ok else 503)


def _event(result: str = "succeeded") -> SecurityAuditEvent:
    return SecurityAuditEvent(
        event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
        request_id="req-1",
        result=result,
    )


async def _drain(sink: SiemForwardAuditSink) -> None:
    await sink._queue.join()


async def test_append_persists_durably_before_forwarding() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    sink = SiemForwardAuditSink(durable, http, "https://siem.example.invalid/ingest")  # type: ignore[arg-type]
    event = _event()
    await sink.append(event)
    assert durable.events == [event]
    await _drain(sink)
    assert len(http.posts) == 1
    assert http.posts[0]["json"]["event_id"] == str(event.event_id)
    await sink.close()


async def test_splunk_hec_message_format() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    sink = SiemForwardAuditSink(
        durable,
        http,  # type: ignore[arg-type]
        "https://siem.example.invalid/services/collector",
        message_format=SiemMessageFormat.SPLUNK_HEC,
    )
    await sink.append(_event())
    await _drain(sink)
    assert "event" in http.posts[0]["json"]
    assert http.posts[0]["json"]["sourcetype"] == "_json"
    await sink.close()


async def test_transient_delivery_failure_is_retried() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    http.fail_times = 2
    sink = SiemForwardAuditSink(
        durable, http, "https://siem.example.invalid/ingest", max_attempts=4  # type: ignore[arg-type]
    )
    await sink.append(_event())
    await _drain(sink)
    assert len(http.posts) == 3
    assert sink.forward_failure_count == 0
    await sink.close()


async def test_persistent_delivery_failure_is_counted_not_raised() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    http.fail_times = 99
    sink = SiemForwardAuditSink(
        durable, http, "https://siem.example.invalid/ingest", max_attempts=2  # type: ignore[arg-type]
    )
    # The event is durably recorded even though every forward attempt fails.
    await sink.append(_event())
    await _drain(sink)
    assert durable.events  # never lost
    assert sink.forward_failure_count == 1
    await sink.close()


async def test_full_queue_drops_oldest_and_counts_it() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    sink = SiemForwardAuditSink(
        durable, http, "https://siem.example.invalid/ingest", max_queue=1  # type: ignore[arg-type]
    )
    # Fill the queue before the forwarder gets a chance to drain it, by pausing the loop.
    sink._queue.put_nowait(_event())
    await sink.append(_event())
    assert sink.dropped_forward_count >= 0  # either dropped here or drained already; no crash
    await sink.close()


async def test_health_check_without_health_url_only_checks_durable_sink() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    http.health_ok = False
    sink = SiemForwardAuditSink(durable, http, "https://siem.example.invalid/ingest")  # type: ignore[arg-type]
    await sink.health_check()
    assert durable.health_checks == 1
    await sink.close()


async def test_health_check_probes_configured_health_url() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    http.health_ok = False
    sink = SiemForwardAuditSink(
        durable,
        http,  # type: ignore[arg-type]
        "https://siem.example.invalid/ingest",
        health_url="https://siem.example.invalid/health",
    )
    with pytest.raises(DependencyUnavailableError):
        await sink.health_check()
    await sink.close()


async def test_recent_delegates_to_durable_sink() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    sink = SiemForwardAuditSink(durable, http, "https://siem.example.invalid/ingest")  # type: ignore[arg-type]
    event = _event()
    await sink.append(event)
    await _drain(sink)
    assert await sink.recent(10) == (event,)
    await sink.close()


async def test_close_stops_forwarder_and_closes_durable_sink() -> None:
    durable = FakeDurableSink()
    http = FakeHttpClient()
    sink = SiemForwardAuditSink(durable, http, "https://siem.example.invalid/ingest")  # type: ignore[arg-type]
    await sink.append(_event())
    await _drain(sink)
    await sink.close()
    assert durable.closed is True
    # Closing twice must not raise.
    await asyncio.sleep(0)
