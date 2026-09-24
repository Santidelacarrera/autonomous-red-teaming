"""Versioned, secret-free messages exchanged with simulation workers."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from art_sim.domain.exceptions import WorkerStateError
from art_sim.platform.models import SimulationRun

_MESSAGE_NAMESPACE = UUID("81a7d08a-8674-49e7-9b91-0aad63b0dc8f")


class SimulationJobV1(BaseModel):
    """Minimal deterministic broker message; it contains no credentials or raw input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    message_id: UUID
    run_id: UUID
    workflow_version: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")
    attempt: int = Field(ge=1, le=100)
    created_at: datetime
    correlation_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")

    @classmethod
    def for_run(cls, run: SimulationRun, attempt: int) -> SimulationJobV1:
        """Build the same message ID for repeated delivery of one logical attempt."""
        identity = f"{run.run_id}:{run.workflow_version}:{attempt}:1"
        return cls(
            message_id=uuid5(_MESSAGE_NAMESPACE, identity),
            run_id=run.run_id,
            workflow_version=run.workflow_version,
            scenario_id=run.scenario_id,
            attempt=attempt,
            created_at=run.created_at,
            correlation_id=run.request_id or str(run.run_id),
        )

    def encode(self) -> bytes:
        """Serialize deterministically as compact UTF-8 JSON."""
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def decode(cls, payload: bytes | str) -> SimulationJobV1:
        """Reject malformed, extra-field, or unknown-version messages safely."""
        if isinstance(payload, bytes) and len(payload) > 16_384:
            raise WorkerStateError("Simulation job exceeds the message size limit")
        if isinstance(payload, str) and len(payload.encode("utf-8")) > 16_384:
            raise WorkerStateError("Simulation job exceeds the message size limit")
        try:
            return cls.model_validate_json(payload)
        except (ValidationError, ValueError) as error:
            raise WorkerStateError("Simulation job contract is invalid") from error


class DispatchReceipt(BaseModel):
    """Provider-neutral acknowledgement for an idempotent dispatch request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    message_id: UUID
    accepted: bool
    duplicate: bool = False


class CancellationReceipt(BaseModel):
    """Provider-neutral acknowledgement of a cooperative cancellation signal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    accepted: bool
    duplicate: bool = False


class PoisonJobRecord(BaseModel):
    """Safe dead-letter record containing no original payload or exception details."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    message_id: UUID
    attempt: int = Field(ge=1)
    reason_code: Literal["MAX_ATTEMPTS_EXCEEDED"] = "MAX_ATTEMPTS_EXCEEDED"
    recorded_at: datetime


class DeadLetterSink(Protocol):
    """Provider-neutral poison-job sink implemented by the deployment boundary."""

    async def publish(self, record: PoisonJobRecord) -> None: ...


class InMemoryDeadLetterSink:
    """Development-only bounded dead-letter collector."""

    def __init__(self, capacity: int = 1000) -> None:
        if capacity < 1:
            raise ValueError("Dead-letter capacity must be positive")
        self._capacity = capacity
        self.records: list[PoisonJobRecord] = []

    async def publish(self, record: PoisonJobRecord) -> None:
        """Append safe poison evidence without retaining the job payload."""
        self.records.append(record)
        if len(self.records) > self._capacity:
            del self.records[: len(self.records) - self._capacity]
