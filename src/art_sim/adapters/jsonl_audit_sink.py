"""Durable append-only security-audit sink — a real, deployment-owned production adapter.

Writes each typed, already-redacted security event as one JSON line to an append-only file
and fsyncs it, so events survive a crash. This satisfies ``DurableSecurityAuditSink`` and is
intended for durable local capture that a log shipper forwards to a SIEM; the schema is the
same typed ``SecurityAuditEvent`` the API emits, so no credential-shaped data can be stored.

Each line is a hash-chained envelope (``art_sim.security.audit_chain``): a monotonically
increasing ``seq`` plus the hash of the previous line. ``verify_audit_log`` can therefore
prove, from the file alone, that no event was lost, duplicated, altered or reordered.
The sink is the **single writer** of its file: two processes appending to one path would
interleave sequence numbers and the verifier would (correctly) flag the result.

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
from art_sim.security.audit_chain import GENESIS_HASH, build_envelope


def _is_json_object(line: str) -> bool:
    """Skip torn fragments left by a crash; the verifier reports them, readers ignore them."""
    try:
        return isinstance(json.loads(line), dict)
    except json.JSONDecodeError:
        return False


def _event_from_line(line: str) -> SecurityAuditEvent:
    """Parse a chained envelope, or a legacy pre-chain line that is the bare event."""
    document = json.loads(line)
    body = document.get("event", document)
    return SecurityAuditEvent.model_validate(body)


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
        self._next_seq, self._head_hash, self._needs_newline = self._recover_head()

    def _recover_head(self) -> tuple[int, str, bool]:
        """Resume the chain after a restart from the last intact envelope in the file.

        A crash can leave a torn final fragment. It is never rewritten or deleted (it is
        evidence); the next append starts on a fresh line and the verifier reports the
        fragment as ``malformed`` without reporting a gap.
        """
        text = self._path.read_text(encoding="utf-8")
        next_seq, head = 1, GENESIS_HASH
        for raw in text.splitlines():
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if (
                isinstance(document, dict)
                and isinstance(document.get("seq"), int)
                and isinstance(document.get("hash"), str)
                and isinstance(document.get("event"), dict)
            ):
                next_seq, head = int(document["seq"]) + 1, str(document["hash"])
        return next_seq, head, bool(text) and not text.endswith("\n")

    async def append(self, event: SecurityAuditEvent) -> None:
        """Append one chained envelope as a JSON line and fsync so it survives a crash."""
        body = event.model_dump(mode="json")
        async with self._lock:
            envelope = build_envelope(self._next_seq, self._head_hash, body)
            line = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
            try:
                await asyncio.to_thread(self._append_sync, line)
            except OSError as error:
                raise DependencyUnavailableError("Audit storage is unavailable") from error
            # Advance the chain only after the line is durable, so a failed write is retried
            # with the same sequence number instead of leaving a gap.
            self._next_seq += 1
            self._head_hash = str(envelope["hash"])

    def _append_sync(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            if self._needs_newline:
                handle.write("\n")
                self._needs_newline = False
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
        events = [_event_from_line(entry) for entry in raw]
        return tuple(reversed(events))

    def _read_tail_sync(self, limit: int) -> list[str]:
        with self._path.open("r", encoding="utf-8") as handle:
            lines = [line.strip() for line in handle if line.strip() and _is_json_object(line)]
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
