"""Async persistence ports required by a restartable simulation service."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from art_sim.platform.models import (
    AuditEvent,
    SimulationRun,
    SimulationRunStatus,
    WorkflowCheckpoint,
)
from art_sim.remediation.models import ApprovalDecision


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

    async def list_events(self, run_id: UUID) -> tuple[AuditEvent, ...]: ...


class ApprovalCoordinator(Protocol):
    """Atomically commit exactly one decision for a waiting run across workers."""

    async def decide(self, run_id: UUID, decision: ApprovalDecision, actor: str) -> SimulationRun: ...
