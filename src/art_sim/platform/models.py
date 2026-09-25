"""Versioned, secret-free durable records for simulation operations."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from art_sim.remediation.models import ApprovalStatus, VerificationStatus


class SimulationRunStatus(StrEnum):
    """Persisted high-level state; terminal states never return to active execution."""

    CREATED = "created"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    RESUMING = "resuming"
    SUCCEEDED = "succeeded"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class SimulationRun(BaseModel):
    """Durable correlation record; artifacts are references, never secret material."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: SimulationRunStatus = SimulationRunStatus.CREATED
    scenario_id: str = Field(min_length=1, max_length=128)
    graph_version: str = Field(min_length=1, max_length=128)
    workflow_version: str = Field(min_length=1, max_length=64)
    created_by: str = Field(min_length=1, max_length=128)
    request_id: str | None = Field(default=None, max_length=64)
    trace_id: UUID | None = None
    risk_before: float | None = Field(default=None, ge=0.0, le=100.0)
    risk_after: float | None = Field(default=None, ge=0.0, le=100.0)
    blast_radius_before: float | None = Field(default=None, ge=0.0, le=100.0)
    blast_radius_after: float | None = Field(default=None, ge=0.0, le=100.0)
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_timestamp: datetime | None = None
    approval_actor: str | None = Field(default=None, max_length=128)
    approval_reason: str | None = Field(default=None, min_length=10, max_length=512)
    review_ready: bool = False
    verification_status: VerificationStatus = VerificationStatus.NOT_RUN
    artifacts: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    error_code: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{1,63}$")
    cancellation_requested: bool = False
    cancellation_requested_at: datetime | None = None
    cancellation_actor: str | None = Field(default=None, max_length=128)


class ExecutionClaim(BaseModel):
    """Durable worker ownership acquired atomically with a lifecycle transition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run: SimulationRun
    owner_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    attempt: int = Field(ge=1)
    fencing_token: int = Field(ge=1)
    lease_expires_at: datetime


class WorkflowCheckpoint(BaseModel):
    """Versioned, JSON-safe snapshot used to resume a paused workflow safely."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    checkpoint_version: int = Field(ge=1)
    state: dict[str, object]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditEvent(BaseModel):
    """Append-only operational evidence without credentials, tokens, or raw payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str = Field(pattern=r"^[a-z]+(?:\.[a-z_]+)+$")
    actor: str = Field(min_length=1, max_length=128)
    status: str = Field(pattern=r"^(succeeded|failed|pending|rejected|cancelled)$")
    metadata: dict[str, str] = Field(default_factory=dict, max_length=20)

    @field_validator("metadata")
    @classmethod
    def reject_sensitive_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject credential-shaped keys before operational evidence reaches a sink."""
        forbidden = {
            "authorization",
            "cookie",
            "password",
            "secret",
            "token",
            "jwt",
            "api_key",
        }
        if any(key.lower() in forbidden for key in value):
            raise ValueError("Audit metadata contains a forbidden field")
        return value
