"""Minimal, redacted security-audit event contracts and sinks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from art_sim.security.redaction import redact_security_text


class AuditDurability(StrEnum):
    """Persistence capability declared by an audit adapter."""

    DISABLED = "disabled"
    VOLATILE = "volatile"
    DURABLE = "durable"


class SecurityEventType(StrEnum):
    """Security-relevant decisions emitted by the HTTP boundary."""

    AUTHENTICATION_SUCCESS = "authentication.success"
    AUTHENTICATION_FAILURE = "authentication.failure"
    AUTHORIZATION_DENIED = "authorization.denied"
    MFA_FAILURE = "authentication.mfa_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit.exceeded"
    LOGOUT = "session.logout"
    SIMULATION_CREATED = "simulation.created"
    SIMULATION_CANCELLED = "simulation.cancelled"
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
    trace_id: UUID | None = None
    source: str = Field(default="api", pattern=r"^[a-z0-9_-]{1,32}$")
    result: str = Field(pattern=r"^(succeeded|failed|denied|limited)$")

    @field_validator("subject", "issuer", "request_id", mode="before")
    @classmethod
    def redact_sensitive_text(cls, value: object) -> object:
        """Apply the same credential redaction policy to every free-text audit field."""
        return redact_security_text(value) if isinstance(value, str) else value


class SecurityAuditSink(Protocol):
    """Append-only sink replaceable by server storage or a SIEM adapter."""

    durability: ClassVar[AuditDurability]

    async def append(self, event: SecurityAuditEvent) -> None: ...

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]: ...


class DurableSecurityAuditSink(SecurityAuditSink, Protocol):
    """Port for durable production retention or a reliable SIEM pipeline.

    Implementations must declare ``durability = AuditDurability.DURABLE``. No external
    service is represented as connected by this interface alone.
    """


class InMemorySecurityAuditSink:
    """Bounded development sink; production must inject shared immutable retention."""

    durability: ClassVar[AuditDurability] = AuditDurability.VOLATILE

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

    durability: ClassVar[AuditDurability] = AuditDurability.DISABLED

    async def append(self, event: SecurityAuditEvent) -> None:
        del event

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        del limit
        return ()
