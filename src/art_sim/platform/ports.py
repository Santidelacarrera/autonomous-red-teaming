"""Async persistence ports required by a restartable simulation service."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Protocol
from uuid import UUID

from art_sim.platform.models import (
    AuditEvent,
    ExecutionClaim,
    SimulationRun,
    SimulationRunStatus,
    WorkflowCheckpoint,
)
from art_sim.remediation.models import ApprovalDecision
from art_sim.worker.models import SimulationArtifacts, SimulationReview


class OperationalStoreCapability(StrEnum):
    """Coordination guarantee declared by an operational-store adapter."""

    SINGLE_NODE = "single_node"
    SERVER_GRADE = "server_grade"


class CheckpointStore(Protocol):
    """Persist and retrieve a versioned workflow snapshot by opaque run identifier."""

    async def save_checkpoint(self, checkpoint: WorkflowCheckpoint) -> None: ...

    async def load_checkpoint(self, run_id: UUID) -> WorkflowCheckpoint: ...


class SimulationRunRepository(Protocol):
    """Persist the current correlation record for a simulation lifecycle."""

    async def create_run(self, run: SimulationRun) -> None: ...

    async def get_run(self, run_id: UUID) -> SimulationRun: ...

    async def update_status(self, run_id: UUID, status: SimulationRunStatus) -> SimulationRun: ...


class AuditRepository(Protocol):
    """Append and list immutable audit events."""

    async def append_event(self, event: AuditEvent) -> None: ...

    async def append_worker_event(
        self, event: AuditEvent, owner_id: str, fencing_token: int
    ) -> None: ...

    async def list_events(self, run_id: UUID) -> tuple[AuditEvent, ...]: ...


class ApprovalCoordinator(Protocol):
    """Atomically commit exactly one decision for a waiting run across workers."""

    async def decide(
        self,
        run_id: UUID,
        decision: ApprovalDecision,
        actor: str,
        reason: str = "Reviewed through a trusted internal coordinator.",
    ) -> SimulationRun: ...


class OperationalStore(Protocol):
    """Complete API persistence contract supplied by a deployment composition root."""

    deployment_capability: ClassVar[OperationalStoreCapability]

    async def initialize(self) -> None: ...

    async def create_run(self, run: SimulationRun) -> None: ...

    async def create_run_idempotent(
        self, run: SimulationRun, idempotency_key: str
    ) -> tuple[SimulationRun, bool]: ...

    async def get_run(self, run_id: UUID) -> SimulationRun: ...

    async def list_runs(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: SimulationRunStatus | None = None,
    ) -> tuple[SimulationRun, ...]: ...

    async def decide(
        self,
        run_id: UUID,
        decision: ApprovalDecision,
        actor: str,
        reason: str = "Reviewed through a trusted internal coordinator.",
    ) -> SimulationRun: ...

    async def acquire_execution(
        self,
        run_id: UUID,
        owner_id: str,
        trace_id: UUID,
        *,
        lease_seconds: int = 300,
        expected_attempt: int | None = None,
    ) -> ExecutionClaim | None: ...

    async def next_execution_attempt(self, run_id: UUID) -> int: ...

    async def renew_execution(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        *,
        lease_seconds: int = 300,
    ) -> bool: ...

    async def release_execution(
        self, run_id: UUID, owner_id: str, fencing_token: int
    ) -> None: ...

    async def mark_waiting_approval(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        review: SimulationReview | None = None,
    ) -> SimulationRun: ...

    async def complete_execution(
        self, artifacts: SimulationArtifacts, owner_id: str, fencing_token: int
    ) -> SimulationRun: ...

    async def reject_execution(
        self, run_id: UUID, owner_id: str, fencing_token: int
    ) -> SimulationRun: ...

    async def fail_execution(
        self, run_id: UUID, owner_id: str, fencing_token: int, error_code: str
    ) -> SimulationRun: ...

    async def request_cancellation(
        self, run_id: UUID, actor: str
    ) -> SimulationRun: ...

    async def cancel_execution(
        self, run_id: UUID, owner_id: str, fencing_token: int
    ) -> SimulationRun: ...

    async def get_result(self, run_id: UUID) -> SimulationArtifacts: ...

    async def get_review(self, run_id: UUID) -> SimulationReview: ...

    async def append_event(self, event: AuditEvent) -> None: ...

    async def append_worker_event(
        self, event: AuditEvent, owner_id: str, fencing_token: int
    ) -> None: ...

    async def list_events(self, run_id: UUID) -> tuple[AuditEvent, ...]: ...


class ServerOperationalStore(OperationalStore, Protocol):
    """Contract for a transactional store shared by independent replicas.

    A conforming adapter must provide atomic compare-and-set, expiring leases,
    monotonically increasing fencing tokens, and immutable result publication. This
    protocol is not evidence that a concrete PostgreSQL or managed-DB adapter exists.
    """

    async def health_check(self) -> None:
        """Verify transactional connectivity without mutating durable state."""

    async def close(self) -> None:
        """Drain and close the server connection pool."""
