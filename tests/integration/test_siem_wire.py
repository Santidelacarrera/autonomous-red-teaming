"""SIEM forwarding over a real HTTP socket (not a hand-written fake client).

The forwarder is exercised with a real ``httpx.AsyncClient`` against a local server that behaves
like a SIEM ingestion endpoint: it can return 5xx before succeeding, require an auth header,
or disappear entirely. The invariant under test is the one the design promises: the durable
local record is complete and verifiable no matter what the SIEM does, and what the SIEM did
receive can be reconciled against it.
"""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import AsyncIterator, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from art_sim.adapters.jsonl_audit_sink import JsonlDurableSecurityAuditSink
from art_sim.adapters.siem_http_audit_sink import SiemForwardAuditSink, SiemMessageFormat
from art_sim.security.audit import AuditRetentionPolicy, SecurityAuditEvent, SecurityEventType
from art_sim.security.audit_chain import durable_event_ids, reconcile_event_ids, verify_audit_log

POLICY = AuditRetentionPolicy(retention_days=30)


class _Siem:
    def __init__(self, *, fail_first: int = 0, token: str | None = None) -> None:
        self.received: list[dict[str, object]] = []
        self.headers: list[dict[str, str]] = []
        self.calls = 0
        siem = self
        self._remaining_failures = fail_first

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                siem.calls += 1
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if token is not None and self.headers.get("Authorization") != f"Splunk {token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                if siem._remaining_failures > 0:
                    siem._remaining_failures -= 1
                    self.send_response(503)
                    self.end_headers()
                    return
                siem.received.append(json.loads(body))
                siem.headers.append(dict(self.headers))
                self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/services/collector"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def make_siem() -> Iterator[type[_Siem]]:
    created: list[_Siem] = []

    class Factory(_Siem):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)  # type: ignore[arg-type]
            created.append(self)

    yield Factory
    for siem in created:
        siem.stop()


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(timeout=3.0) as client:
        yield client


def _event(i: int) -> SecurityAuditEvent:
    return SecurityAuditEvent(
        event_type=SecurityEventType.APPROVAL_APPROVED, subject=f"user{i}", request_id=f"req-{i}", result="succeeded"
    )


async def test_events_arrive_exactly_once_in_hec_format_with_credentials(
    tmp_path: Path, make_siem: type[_Siem], http: httpx.AsyncClient
) -> None:
    siem = make_siem(token="s3cr3t-hec-token")
    sink = SiemForwardAuditSink(
        JsonlDurableSecurityAuditSink(tmp_path / "a.jsonl", POLICY),
        http,
        siem.url,
        message_format=SiemMessageFormat.SPLUNK_HEC,
        headers={"Authorization": "Splunk s3cr3t-hec-token"},
        source="art-sim-test",
    )
    for i in range(5):
        await sink.append(_event(i))
    await sink._queue.join()
    await sink.close()

    assert len(siem.received) == 5
    assert all(item["sourcetype"] == "_json" and item["source"] == "art-sim-test" for item in siem.received)
    ids = [str(item["event"]["event_id"]) for item in siem.received]  # type: ignore[index]
    assert reconcile_event_ids(durable_event_ids(tmp_path / "a.jsonl"), ids).ok
    assert verify_audit_log(tmp_path / "a.jsonl").ok
    # The credential travels in a header only, never inside an event body that gets stored.
    assert "s3cr3t-hec-token" not in (tmp_path / "a.jsonl").read_text()


async def test_transient_5xx_is_retried_until_delivery(
    tmp_path: Path, make_siem: type[_Siem], http: httpx.AsyncClient
) -> None:
    siem = make_siem(fail_first=2)
    sink = SiemForwardAuditSink(
        JsonlDurableSecurityAuditSink(tmp_path / "a.jsonl", POLICY), http, siem.url, max_attempts=4
    )
    await sink.append(_event(1))
    await sink._queue.join()
    await sink.close()
    assert siem.calls == 3 and len(siem.received) == 1  # two 503s, then success
    assert sink.forward_failure_count == 0


async def test_wrong_credentials_are_counted_not_silently_lost(
    tmp_path: Path, make_siem: type[_Siem], http: httpx.AsyncClient
) -> None:
    siem = make_siem(token="right")
    sink = SiemForwardAuditSink(
        JsonlDurableSecurityAuditSink(tmp_path / "a.jsonl", POLICY),
        http,
        siem.url,
        headers={"Authorization": "Splunk wrong"},
        max_attempts=1,
    )
    await sink.append(_event(1))
    await sink._queue.join()
    await sink.close()
    assert siem.received == []
    assert sink.forward_failure_count == 1  # an operator can alert on this
    assert len(durable_event_ids(tmp_path / "a.jsonl")) == 1  # and backfill from here


async def test_siem_outage_never_loses_a_durable_event(tmp_path: Path, http: httpx.AsyncClient) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
    sink = SiemForwardAuditSink(
        JsonlDurableSecurityAuditSink(tmp_path / "a.jsonl", POLICY),
        http,
        f"http://127.0.0.1:{dead}/ingest",
        max_attempts=1,
    )
    for i in range(4):
        await sink.append(_event(i))  # the request path is never blocked or failed by the SIEM
    await sink._queue.join()
    await sink.close()
    assert sink.forward_failure_count == 4
    report = verify_audit_log(tmp_path / "a.jsonl")
    assert report.ok and report.chained_events == 4


async def test_readiness_reflects_the_siem_when_a_health_url_is_configured(
    tmp_path: Path, make_siem: type[_Siem], http: httpx.AsyncClient
) -> None:
    from art_sim.domain.exceptions import DependencyUnavailableError

    siem = make_siem()
    durable = JsonlDurableSecurityAuditSink(tmp_path / "a.jsonl", POLICY)
    sink = SiemForwardAuditSink(durable, http, siem.url, health_url=siem.url)
    await sink.health_check()
    siem.stop()
    with pytest.raises(DependencyUnavailableError):
        await sink.health_check()
    await sink.close()
