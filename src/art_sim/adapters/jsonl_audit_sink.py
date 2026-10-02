"""Durable append-only security-audit sink — a real, deployment-owned production adapter.

Writes each typed, already-redacted security event as one JSON line to an append-only file
and fsyncs it, so events survive a crash. This satisfies ``DurableSecurityAuditSink`` and is
intended for durable local capture that a log shipper forwards to a SIEM; the schema is the
same typed ``SecurityAuditEvent`` the API emits, so no credential-shaped data can be stored.

Writes are serialized through an async lock and executed off the event loop.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import ClassVar

from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.security.audit import (
    AuditDurability,
    AuditRetentionPolicy,
    SecurityAuditEvent,
)


class JsonlDurableSecurityAuditSink:
    """Append-only JSONL sink with fsync durability and a bounded recent-tail read."""

    durability: ClassVar[AuditDurability] = AuditDurability.DURABLE

    def __init__(self, path: Path, retention_policy: AuditRetentionPolicy) -> None:
        """Create the sink over a durable append-only file path (parent must exist)."""
        self.retention_policy = retention_policy
        self._path = path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    async def append(self, event: SecurityAuditEvent) -> None:
        """Append one event as a JSON line and fsync so it survives a crash."""
        line = json.dumps(event.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
        async with self._lock:
            try:
                await asyncio.to_thread(self._append_sync, line)
            except OSError as error:
                raise DependencyUnavailableError("Audit storage is unavailable") from error

    def _append_sync(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        """Return the newest-first events from the tail of the durable log."""
        if not 1 <= limit <= 200:
            raise ValueError("Audit limit must be 1..200")
        async with self._lock:
            try:
                raw = await asyncio.to_thread(self._read_tail_sync, limit)
            except OSError as error:
                raise DependencyUnavailableError("Audit storage is unavailable") from error
        events = [SecurityAuditEvent.model_validate_json(entry) for entry in raw]
        return tuple(reversed(events))

    def _read_tail_sync(self, limit: int) -> list[str]:
        with self._path.open("r", encoding="utf-8") as handle:
            lines = [line.strip() for line in handle if line.strip()]
        return lines[-limit:]

    async def health_check(self) -> None:
        """Verify the durable append path is writable without emitting a synthetic event."""
        try:
            await asyncio.to_thread(self._probe_sync)
        except OSError as error:
            raise DependencyUnavailableError("Audit storage is unavailable") from error

    def _probe_sync(self) -> None:
        # Open for append (creates nothing new) to confirm the descriptor is writable.
        with self._path.open("a", encoding="utf-8"):
            pass

    async def close(self) -> None:
        """No persistent handle is held; nothing to release."""
