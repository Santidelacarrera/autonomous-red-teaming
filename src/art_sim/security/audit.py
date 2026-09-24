"""Minimal, redacted security-audit event contracts and sinks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventType(StrEnum):
    """Security-relevant decisions emitted by the HTTP boundary."""

    AUTHENTICATION_SUCCESS = "authentication.success"
    AUTHENTICATION_FAILURE = "authentication.failure"
    AUTHORIZATION_DENIED = "authorization.denied"
    RATE_LIMIT_EXCEEDED = "rate_limit.exceeded"
    LOGOUT = "session.logout"
    SIMULATION_CREATED = "simulation.created"
    APPROVAL_APPROVED = "approval.approved"
    APPROVAL_REJECTED = "approval.rejected"
    ADMIN_READ = "admin.security_read"


class SecurityAuditEvent(BaseModel):
    """Append-only event whose schema cannot accept credentials or arbitrary payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: SecurityEventType
    subject: str | None = Field(default=None, max_length=128)
    issuer: str | None = Field(default=None, max_length=512)
    request_id: str = Field(min_length=1, max_length=64)
    run_id: UUID | None = None
    source: str = Field(default="api", pattern=r"^[a-z0-9_-]{1,32}$")
    result: str = Field(pattern=r"^(succeeded|failed|denied|limited)$")


class SecurityAuditSink(Protocol):
    """Append-only sink replaceable by server storage or a SIEM adapter."""

    async def append(self, event: SecurityAuditEvent) -> None: ...

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]: ...


class InMemorySecurityAuditSink:
    """Bounded development sink; production must inject shared immutable retention."""

    def __init__(self, capacity: int = 1000) -> None:
        if capacity < 1:
            raise ValueError("Audit capacity must be positive")
        self._capacity = capacity
        self._events: list[SecurityAuditEvent] = []
        self._lock = asyncio.Lock()

    async def append(self, event: SecurityAuditEvent) -> None:
        """Append one typed event and retain only bounded recent history."""
        async with self._lock:
            self._events.append(event)
            if len(self._events) > self._capacity:
                del self._events[: len(self._events) - self._capacity]

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        """Return a newest-first immutable snapshot."""
        if not 1 <= limit <= 200:
            raise ValueError("Audit limit must be 1..200")
        async with self._lock:
            return tuple(reversed(self._events[-limit:]))


class NullSecurityAuditSink:
    """No-op sink retained only for backward-compatible isolated unit composition."""

    async def append(self, event: SecurityAuditEvent) -> None:
        del event

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        del limit
        return ()
