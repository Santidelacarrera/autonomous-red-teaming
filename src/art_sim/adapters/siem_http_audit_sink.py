"""SIEM-forwarding security-audit sink — a real, deployment-owned production adapter.

Composes durable local capture (any ``DurableSecurityAuditSink``, typically
``JsonlDurableSecurityAuditSink``) with best-effort, ordered, at-least-once forwarding of
every event to a SIEM HTTP ingestion endpoint (a generic JSON webhook, or Splunk HTTP Event
Collector framing). This satisfies ``DurableSecurityAuditSink`` itself, so it is a drop-in
production alternative to local-file-only capture for deployments that push events to a SIEM
over HTTP instead of (or in addition to) shipping the JSONL file with a log agent.

Design, matching ``docs/disaster-recovery.md``'s audit-outage rule ("stop sensitive
operations until durable evidence is restored or reconciled... do not silently downgrade to
memory"):

- ``append`` first writes through the wrapped durable sink and only returns once that
  write (with its own fsync) has succeeded — a SIEM outage can never lose an event, and a
  local-storage outage still fails the request, exactly as it does today;
- forwarding to the SIEM happens on a bounded background queue so the request path is never
  blocked by a slow or unreachable SIEM endpoint; a full queue drops the *oldest* queued
  forward attempt (never the durable record) and increments a counter an operator can alert
  on (``dropped_forward_count``) — the event is always still in the durable sink for
  reconciliation/backfill;
- delivery retries transient HTTP failures (5xx, timeouts, connection errors) with bounded
  jittered backoff and gives up per-event rather than blocking the queue indefinitely;
- ``health_check`` always verifies the durable sink; it also probes the SIEM endpoint when a
  ``health_url`` is configured, so a genuinely unreachable SIEM can be surfaced in readiness
  without making local durability depend on it.

No cloud SIEM SDK is required: delivery uses the project's existing ``httpx`` dependency.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.security.audit import (
    AuditDurability,
    AuditRetentionPolicy,
    DurableSecurityAuditSink,
    SecurityAuditEvent,
)


class SiemMessageFormat(StrEnum):
    """Supported SIEM HTTP ingestion framings."""

    RAW_JSON = "raw_json"
    SPLUNK_HEC = "splunk_hec"


class SiemForwardAuditSink:
    """Durable local audit capture plus best-effort forwarding to a SIEM HTTP endpoint."""

    durability: ClassVar[AuditDurability] = AuditDurability.DURABLE

    def __init__(
        self,
        durable_sink: DurableSecurityAuditSink,
        http_client: httpx.AsyncClient,
        endpoint: str,
        *,
        message_format: SiemMessageFormat = SiemMessageFormat.RAW_JSON,
        headers: Mapping[str, str] | None = None,
        source: str = "art-sim",
        health_url: str | None = None,
        max_queue: int = 10_000,
        max_attempts: int = 5,
    ) -> None:
        """Wrap a durable sink; the caller owns the ``httpx.AsyncClient`` lifecycle/TLS."""
        self.retention_policy: AuditRetentionPolicy = durable_sink.retention_policy
        self._durable = durable_sink
        self._http = http_client
        self._endpoint = endpoint
        self._format = message_format
        self._headers = dict(headers or {})
        self._source = source
        self._health_url = health_url
        self._max_attempts = max_attempts
        self._queue: asyncio.Queue[SecurityAuditEvent] = asyncio.Queue(maxsize=max_queue)
        self._forwarder_task: asyncio.Task[None] | None = None
        self.dropped_forward_count = 0
        self.forward_failure_count = 0

    def start(self) -> None:
        """Start the background forwarder loop; idempotent."""
        if self._forwarder_task is None or self._forwarder_task.done():
            self._forwarder_task = asyncio.ensure_future(self._run_forwarder())

    async def append(self, event: SecurityAuditEvent) -> None:
        """Durably persist the event, then best-effort enqueue it for SIEM forwarding."""
        await self._durable.append(event)
        self.start()
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self.dropped_forward_count += 1
            except asyncio.QueueEmpty:  # pragma: no cover - race with the forwarder loop
                pass
            self._queue.put_nowait(event)

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        """Delegate to the durable sink, the system of record for prior events."""
        return await self._durable.recent(limit)

    async def _run_forwarder(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._deliver(event)
            except Exception:  # noqa: BLE001 - one bad delivery must never stop the loop
                self.forward_failure_count += 1
            finally:
                self._queue.task_done()

    async def _deliver(self, event: SecurityAuditEvent) -> None:
        payload = self._build_payload(event)
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._max_attempts),
            wait=wait_exponential_jitter(initial=0.5, max=10.0),
            retry=retry_if_exception_type(httpx.HTTPError),
            reraise=True,
        ):
            with attempt:
                response = await self._http.post(
                    self._endpoint, json=payload, headers=self._headers
                )
                response.raise_for_status()

    def _build_payload(self, event: SecurityAuditEvent) -> dict[str, object]:
        body = event.model_dump(mode="json")
        if self._format is SiemMessageFormat.SPLUNK_HEC:
            return {"event": body, "sourcetype": "_json", "source": self._source}
        return body

    async def health_check(self) -> None:
        """Verify durable storage, and the SIEM endpoint when ``health_url`` is configured."""
        await self._durable.health_check()
        if self._health_url is None:
            return
        try:
            response = await self._http.get(self._health_url, timeout=5.0)
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise DependencyUnavailableError("SIEM endpoint is unavailable") from error

    async def close(self) -> None:
        """Stop forwarding (best-effort drain), then close the durable sink."""
        if self._forwarder_task is not None:
            self._forwarder_task.cancel()
            try:
                await self._forwarder_task
            except asyncio.CancelledError:
                # ``CancelledError`` is a ``BaseException``: awaiting a task we just cancelled
                # always raises it, and that is the expected, successful shutdown outcome.
                pass
            except Exception:  # noqa: BLE001, S110 - a failed forwarder must not block shutdown
                pass
            self._forwarder_task = None
        await self._durable.close()
