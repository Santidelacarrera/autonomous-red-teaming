"""PostgreSQL operational store — the server-grade production persistence adapter.

Implements the full ``OperationalStore`` / ``ServerOperationalStore`` contract on PostgreSQL
with asyncpg, mirroring the logic of the SQLite development store. It is the coordination
authority for distributed workers: one live owner per run, expiring leases, monotonic
fencing tokens, idempotent API creation, approval compare-and-set, immutable results/reviews,
and an append-only audit trail.

Concurrency: each read-modify-write operation opens a transaction and takes a row lock on the
run (``SELECT ... FOR UPDATE``), which is the PostgreSQL equivalent of the SQLite store's
``BEGIN IMMEDIATE`` write serialization. Timestamps are stored as ``timestamptz`` and compared
by the database, not as strings.

``asyncpg`` is an opt-in extra (``pip install .[postgres]``). Core code never imports it.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar
from uuid import UUID

import asyncpg

from art_sim.domain.exceptions import ApprovalRequiredError, ConfigurationError
from art_sim.platform.lifecycle import SimulationRunStateMachine
from art_sim.platform.models import (
    AuditEvent,
    ExecutionClaim,
    SimulationRun,
    SimulationRunStatus,
    WorkflowCheckpoint,
)
from art_sim.platform.ports import OperationalStoreCapability
from art_sim.platform.sqlite import CheckpointCorruptionError, OperationalStoreError
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus
from art_sim.worker.models import SimulationArtifacts, SimulationReview

_SCHEMA = """
CREATE TABLE IF NOT EXISTS simulation_runs (
  run_id UUID PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL,
  approval_status TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_checkpoints (
  run_id UUID PRIMARY KEY REFERENCES simulation_runs(run_id), payload TEXT NOT NULL,
  checksum TEXT NOT NULL, checkpoint_version INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, event_id UUID UNIQUE NOT NULL,
  run_id UUID NOT NULL REFERENCES simulation_runs(run_id), payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_idempotency (
  idempotency_key TEXT PRIMARY KEY, run_id UUID NOT NULL REFERENCES simulation_runs(run_id),
  scenario_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS worker_leases (
  run_id UUID PRIMARY KEY REFERENCES simulation_runs(run_id), owner_id TEXT NOT NULL,
  attempt INTEGER NOT NULL, fencing_token BIGINT NOT NULL, acquired_at TIMESTAMPTZ NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS simulation_results (
  run_id UUID PRIMARY KEY REFERENCES simulation_runs(run_id), workflow_version TEXT NOT NULL,
  payload TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS simulation_reviews (
  run_id UUID PRIMARY KEY REFERENCES simulation_runs(run_id), workflow_version TEXT NOT NULL,
  payload TEXT NOT NULL, checksum TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
"""

_EXECUTABLE = frozenset(
    {SimulationRunStatus.CREATED, SimulationRunStatus.RUNNING, SimulationRunStatus.RESUMING}
)


class PostgresOperationalStore:
    """Server-grade asyncpg operational store implementing the full coordination contract."""

    deployment_capability: ClassVar[OperationalStoreCapability] = (
        OperationalStoreCapability.SERVER_GRADE
    )

    def __init__(self, pool: asyncpg.Pool, *, clock: Callable[[], datetime] | None = None) -> None:
        """Inject a configured asyncpg pool; the deployment owns its lifecycle and DSN."""
        self._pool = pool
        self._clock = clock or (lambda: datetime.now(UTC))

    @classmethod
    async def from_dsn(cls, dsn: str, *, min_size: int = 2, max_size: int = 20) -> PostgresOperationalStore:
        """Build a store over a new connection pool for the given DSN."""
        pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
        if pool is None:  # pragma: no cover - defensive
            raise ConfigurationError("Unable to create a PostgreSQL connection pool")
        return cls(pool)

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ConfigurationError("Operational store clock must be timezone-aware")
        return now

    async def initialize(self) -> None:
        """Create the schema idempotently before accepting any work."""
        async with self._pool.acquire() as conn:
            await conn.execute(_SCHEMA)

    # ---- checkpoints -------------------------------------------------------------------

    async def save_checkpoint(self, checkpoint: WorkflowCheckpoint) -> None:
        payload = checkpoint.model_dump_json()
        checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        async with self._pool.acquire() as conn, conn.transaction():
            exists = await conn.fetchval(
                "SELECT 1 FROM simulation_runs WHERE run_id=$1", checkpoint.run_id
            )
            if exists is None:
                raise OperationalStoreError("Cannot checkpoint an unknown simulation run")
            await conn.execute(
                """INSERT INTO workflow_checkpoints(run_id,payload,checksum,checkpoint_version,created_at)
                   VALUES($1,$2,$3,$4,$5)
                   ON CONFLICT(run_id) DO UPDATE SET payload=excluded.payload,
                     checksum=excluded.checksum,checkpoint_version=excluded.checkpoint_version,
                     created_at=excluded.created_at""",
                checkpoint.run_id, payload, checksum, checkpoint.checkpoint_version, checkpoint.created_at,
            )

    async def load_checkpoint(self, run_id: UUID) -> WorkflowCheckpoint:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT payload,checksum FROM workflow_checkpoints WHERE run_id=$1", run_id
            )
        if row is None:
            raise OperationalStoreError("Checkpoint does not exist")
        payload = str(row["payload"])
        if not hmac.compare_digest(hashlib.sha256(payload.encode("utf-8")).hexdigest(), str(row["checksum"])):
            raise CheckpointCorruptionError("Checkpoint integrity verification failed")
        try:
            return WorkflowCheckpoint.model_validate_json(payload)
        except ValueError as error:
            raise CheckpointCorruptionError("Checkpoint schema validation failed") from error

    # ---- run creation / reads ----------------------------------------------------------

    async def create_run(self, run: SimulationRun) -> None:
        async with self._pool.acquire() as conn, conn.transaction():
            try:
                await conn.execute(
                    "INSERT INTO simulation_runs(run_id,payload,status,approval_status,updated_at) VALUES($1,$2,$3,$4,$5)",
                    run.run_id, run.model_dump_json(), run.status.value, run.approval_status.value, run.updated_at,
                )
            except asyncpg.UniqueViolationError as error:
                raise OperationalStoreError("Simulation run already exists") from error
            await self._append_event(conn, AuditEvent(run_id=run.run_id, event_type="simulation.created", actor=run.created_by, status="pending"))

    async def create_run_idempotent(self, run: SimulationRun, idempotency_key: str) -> tuple[SimulationRun, bool]:
        if not 8 <= len(idempotency_key) <= 128 or not idempotency_key.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Idempotency key is invalid")
        async with self._pool.acquire() as conn, conn.transaction():
            existing = await conn.fetchrow(
                "SELECT run_id,scenario_id FROM api_idempotency WHERE idempotency_key=$1 FOR UPDATE", idempotency_key
            )
            if existing is not None:
                if existing["scenario_id"] != run.scenario_id:
                    raise OperationalStoreError("Idempotency key was already used for another scenario")
                payload = await conn.fetchval("SELECT payload FROM simulation_runs WHERE run_id=$1", existing["run_id"])
                if payload is None:
                    raise OperationalStoreError("Idempotency record references an unavailable run")
                return SimulationRun.model_validate_json(str(payload)), False
            try:
                await conn.execute(
                    "INSERT INTO simulation_runs(run_id,payload,status,approval_status,updated_at) VALUES($1,$2,$3,$4,$5)",
                    run.run_id, run.model_dump_json(), run.status.value, run.approval_status.value, run.updated_at,
                )
                await conn.execute(
                    "INSERT INTO api_idempotency(idempotency_key,run_id,scenario_id) VALUES($1,$2,$3)",
                    idempotency_key, run.run_id, run.scenario_id,
                )
            except asyncpg.UniqueViolationError as error:
                raise OperationalStoreError("Simulation run could not be created") from error
            await self._append_event(conn, AuditEvent(run_id=run.run_id, event_type="simulation.created", actor=run.created_by, status="pending"))
            return run, True

    async def get_run(self, run_id: UUID) -> SimulationRun:
        async with self._pool.acquire() as conn:
            payload = await conn.fetchval("SELECT payload FROM simulation_runs WHERE run_id=$1", run_id)
        if payload is None:
            raise OperationalStoreError("Simulation run does not exist")
        return SimulationRun.model_validate_json(str(payload))

    async def list_runs(self, *, limit: int = 50, offset: int = 0, status: SimulationRunStatus | None = None) -> tuple[SimulationRun, ...]:
        if not 1 <= limit <= 200 or offset < 0:
            raise ValueError("limit must be 1..200 and offset must not be negative")
        async with self._pool.acquire() as conn:
            if status is not None:
                rows = await conn.fetch(
                    "SELECT payload FROM simulation_runs WHERE status=$1 ORDER BY updated_at DESC, run_id DESC LIMIT $2 OFFSET $3",
                    status.value, limit, offset,
                )
            else:
                rows = await conn.fetch(
                    "SELECT payload FROM simulation_runs ORDER BY updated_at DESC, run_id DESC LIMIT $1 OFFSET $2",
                    limit, offset,
                )
        return tuple(SimulationRun.model_validate_json(str(row["payload"])) for row in rows)

    async def update_status(self, run_id: UUID, status: SimulationRunStatus) -> SimulationRun:
        async with self._pool.acquire() as conn, conn.transaction():
            run = await self._locked_run(conn, run_id)
            if run.status in SimulationRunStateMachine.TERMINAL:
                raise OperationalStoreError("Terminal simulation runs cannot be updated")
            SimulationRunStateMachine.require(run.status, status)
            updated = run.model_copy(update={"status": status, "updated_at": self._now()})
            await self._write_run(conn, updated)
            return updated

    # ---- audit -------------------------------------------------------------------------

    async def append_event(self, event: AuditEvent) -> None:
        async with self._pool.acquire() as conn:
            await self._append_event(conn, event)

    async def append_worker_event(self, event: AuditEvent, owner_id: str, fencing_token: int) -> None:
        async with self._pool.acquire() as conn, conn.transaction():
            await self._owned_run(conn, event.run_id, owner_id, fencing_token)
            await self._append_event(conn, event)

    async def list_events(self, run_id: UUID) -> tuple[AuditEvent, ...]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT payload FROM audit_events WHERE run_id=$1 ORDER BY sequence", run_id)
        return tuple(AuditEvent.model_validate_json(str(row["payload"])) for row in rows)

    # ---- approval CAS ------------------------------------------------------------------

    async def decide(self, run_id: UUID, decision: ApprovalDecision, actor: str, reason: str = "Reviewed through a trusted internal coordinator.") -> SimulationRun:
        if not actor.strip():
            raise ApprovalRequiredError("Approval actor is required")
        if not 10 <= len(reason.strip()) <= 512:
            raise ApprovalRequiredError("Approval reason must contain 10 to 512 characters")
        reason = reason.strip()
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "SELECT payload,status,approval_status FROM simulation_runs WHERE run_id=$1 FOR UPDATE", run_id
            )
            if row is None:
                raise OperationalStoreError("Simulation run does not exist")
            if row["status"] != SimulationRunStatus.WAITING_APPROVAL.value or row["approval_status"] != ApprovalStatus.PENDING.value:
                raise ApprovalRequiredError("Only a pending waiting run can receive a decision")
            run = SimulationRun.model_validate_json(str(row["payload"]))
            approval_status = ApprovalStatus.APPROVED if decision is ApprovalDecision.APPROVED else ApprovalStatus.REJECTED
            SimulationRunStateMachine.require(run.status, SimulationRunStatus.RESUMING)
            now = self._now()
            updated = run.model_copy(update={
                "approval_status": approval_status, "approval_timestamp": now, "approval_actor": actor,
                "approval_reason": reason, "status": SimulationRunStatus.RESUMING, "updated_at": now,
            })
            await self._write_run(conn, updated)
            await self._append_event(conn, AuditEvent(
                run_id=run_id, event_type=f"simulation.{decision.value}", actor=actor,
                status="succeeded" if decision is ApprovalDecision.APPROVED else "rejected",
            ))
            return updated

    # ---- execution ownership / lease / fencing ----------------------------------------

    async def acquire_execution(self, run_id: UUID, owner_id: str, trace_id: UUID, *, lease_seconds: int = 300, expected_attempt: int | None = None) -> ExecutionClaim | None:
        if not owner_id or len(owner_id) > 128 or lease_seconds < 1:
            raise ValueError("Worker ownership parameters are invalid")
        now = self._now()
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow("SELECT payload FROM simulation_runs WHERE run_id=$1 FOR UPDATE", run_id)
            if row is None:
                raise OperationalStoreError("Simulation run does not exist")
            run = SimulationRun.model_validate_json(str(row["payload"]))
            if run.status not in _EXECUTABLE:
                return None
            lease = await conn.fetchrow("SELECT attempt,fencing_token,lease_expires_at FROM worker_leases WHERE run_id=$1", run_id)
            if lease is not None and lease["lease_expires_at"] > now:
                return None
            attempt = int(lease["attempt"]) + 1 if lease is not None else 1
            if expected_attempt is not None and expected_attempt != attempt:
                return None
            fencing_token = int(lease["fencing_token"]) + 1 if lease is not None else 1
            original_status = run.status
            if run.status is not SimulationRunStatus.RUNNING:
                SimulationRunStateMachine.require(run.status, SimulationRunStatus.RUNNING)
            updated = run.model_copy(update={"status": SimulationRunStatus.RUNNING, "trace_id": trace_id, "updated_at": now})
            expires_at = now + timedelta(seconds=lease_seconds)
            await conn.execute(
                """INSERT INTO worker_leases(run_id,owner_id,attempt,fencing_token,acquired_at,lease_expires_at)
                   VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(run_id) DO UPDATE SET
                     owner_id=excluded.owner_id,attempt=excluded.attempt,fencing_token=excluded.fencing_token,
                     acquired_at=excluded.acquired_at,lease_expires_at=excluded.lease_expires_at""",
                run_id, owner_id, attempt, fencing_token, now, expires_at,
            )
            await self._write_run(conn, updated)
            await self._append_event(conn, AuditEvent(
                run_id=run_id,
                event_type="simulation.started" if original_status is SimulationRunStatus.CREATED else "simulation.resumed",
                actor=f"worker:{owner_id}", status="succeeded",
                metadata={"trace_id": str(trace_id), "attempt": str(attempt), "fencing_token": str(fencing_token)},
            ))
            return ExecutionClaim(run=updated, owner_id=owner_id, attempt=attempt, fencing_token=fencing_token, lease_expires_at=expires_at)

    async def next_execution_attempt(self, run_id: UUID) -> int:
        async with self._pool.acquire() as conn:
            status = await conn.fetchval("SELECT status FROM simulation_runs WHERE run_id=$1", run_id)
            if status is None:
                raise OperationalStoreError("Simulation run does not exist")
            if SimulationRunStatus(str(status)) not in _EXECUTABLE:
                raise OperationalStoreError("Simulation run is not executable")
            attempt = await conn.fetchval("SELECT attempt FROM worker_leases WHERE run_id=$1", run_id)
        return int(attempt) + 1 if attempt is not None else 1

    async def renew_execution(self, run_id: UUID, owner_id: str, fencing_token: int, *, lease_seconds: int = 300) -> bool:
        if lease_seconds < 1:
            raise ValueError("Lease duration must be positive")
        now = self._now()
        expires_at = now + timedelta(seconds=lease_seconds)
        async with self._pool.acquire() as conn, conn.transaction():
            updated = await conn.fetchval(
                """UPDATE worker_leases SET lease_expires_at=$1
                   WHERE run_id=$2 AND owner_id=$3 AND fencing_token=$4 AND lease_expires_at>$5
                   RETURNING run_id""",
                expires_at, run_id, owner_id, fencing_token, now,
            )
            return updated is not None

    async def release_execution(self, run_id: UUID, owner_id: str, fencing_token: int) -> None:
        now = self._now()
        async with self._pool.acquire() as conn, conn.transaction():
            await self._owned_run(conn, run_id, owner_id, fencing_token)
            await conn.execute(
                "UPDATE worker_leases SET lease_expires_at=$1 WHERE run_id=$2 AND owner_id=$3 AND fencing_token=$4",
                now, run_id, owner_id, fencing_token,
            )
            await self._append_event(conn, AuditEvent(
                run_id=run_id, event_type="simulation.lease_released", actor=f"worker:{owner_id}",
                status="pending", metadata={"fencing_token": str(fencing_token)},
            ))

    async def mark_waiting_approval(self, run_id: UUID, owner_id: str, fencing_token: int, review: SimulationReview | None = None) -> SimulationRun:
        async with self._pool.acquire() as conn, conn.transaction():
            run = await self._owned_run(conn, run_id, owner_id, fencing_token)
            now = self._now()
            target = SimulationRunStatus.CANCELLED if run.cancellation_requested else SimulationRunStatus.WAITING_APPROVAL
            SimulationRunStateMachine.require(run.status, target)
            if review is not None:
                if review.run_id != run_id or review.scenario_id != run.scenario_id or review.workflow_version != run.workflow_version:
                    raise OperationalStoreError("Security review does not match its simulation run")
                review_payload = review.model_dump_json()
                await conn.execute(
                    "INSERT INTO simulation_reviews(run_id,workflow_version,payload,checksum,created_at) VALUES($1,$2,$3,$4,$5)",
                    run_id, review.workflow_version, review_payload,
                    hashlib.sha256(review_payload.encode("utf-8")).hexdigest(), review.generated_at,
                )
            updated = run.model_copy(update={"status": target, "review_ready": review is not None, "updated_at": now})
            await self._write_run(conn, updated)
            await conn.execute("UPDATE worker_leases SET lease_expires_at=$1 WHERE run_id=$2", now, run_id)
            await self._append_event(conn, AuditEvent(
                run_id=run_id,
                event_type="simulation.cancelled" if target is SimulationRunStatus.CANCELLED else "simulation.waiting_approval",
                actor=f"worker:{owner_id}", status="cancelled" if target is SimulationRunStatus.CANCELLED else "pending",
            ))
            return updated

    async def complete_execution(self, artifacts: SimulationArtifacts, owner_id: str, fencing_token: int) -> SimulationRun:
        async with self._pool.acquire() as conn, conn.transaction():
            run = await self._owned_run(conn, artifacts.run_id, owner_id, fencing_token)
            SimulationRunStateMachine.require(run.status, SimulationRunStatus.SUCCEEDED)
            if run.cancellation_requested:
                raise OperationalStoreError("Cancellation prevents result publication")
            if run.workflow_version != artifacts.workflow_version or run.scenario_id != artifacts.scenario_id:
                raise OperationalStoreError("Result artifact does not match its simulation run")
            try:
                await conn.execute(
                    "INSERT INTO simulation_results(run_id,workflow_version,payload,created_at) VALUES($1,$2,$3,$4)",
                    artifacts.run_id, artifacts.workflow_version, artifacts.model_dump_json(), artifacts.generated_at,
                )
            except asyncpg.UniqueViolationError as error:
                raise OperationalStoreError("Simulation result already exists") from error
            now = self._now()
            updated = run.model_copy(update={
                "status": SimulationRunStatus.SUCCEEDED, "graph_version": artifacts.graph_version,
                "risk_before": artifacts.risk.score, "risk_after": artifacts.verification.risk_after,
                "blast_radius_before": artifacts.blast_radius.blast_radius_percentage,
                "blast_radius_after": artifacts.verification.blast_radius_after.blast_radius_percentage,
                "verification_status": artifacts.verification.status,
                "artifacts": tuple(a.file_path for a in artifacts.remediation_artifacts) + ("report.md",),
                "updated_at": now,
            })
            await self._write_run(conn, updated)
            await conn.execute("UPDATE worker_leases SET lease_expires_at=$1 WHERE run_id=$2", now, artifacts.run_id)
            await self._append_event(conn, AuditEvent(
                run_id=artifacts.run_id, event_type="simulation.completed", actor=f"worker:{owner_id}",
                status="succeeded", metadata={"trace_id": str(artifacts.trace_id)},
            ))
            return updated

    async def reject_execution(self, run_id: UUID, owner_id: str, fencing_token: int) -> SimulationRun:
        return await self._finish_without_result(run_id, owner_id, fencing_token, rejected=True)

    async def fail_execution(self, run_id: UUID, owner_id: str, fencing_token: int, error_code: str) -> SimulationRun:
        if not error_code or len(error_code) > 64 or not error_code.replace("_", "").isalnum():
            raise ValueError("Worker error code is invalid")
        return await self._finish_without_result(run_id, owner_id, fencing_token, rejected=False, error_code=error_code)

    async def _finish_without_result(self, run_id: UUID, owner_id: str, fencing_token: int, *, rejected: bool, error_code: str = "SIMULATION_REJECTED") -> SimulationRun:
        async with self._pool.acquire() as conn, conn.transaction():
            run = await self._owned_run(conn, run_id, owner_id, fencing_token)
            target = (
                SimulationRunStatus.CANCELLED if run.cancellation_requested
                else SimulationRunStatus.REJECTED if rejected
                else SimulationRunStatus.FAILED
            )
            SimulationRunStateMachine.require(run.status, target)
            now = self._now()
            updated = run.model_copy(update={
                "status": target,
                "error_code": None if rejected or target is SimulationRunStatus.CANCELLED else error_code,
                "updated_at": now,
            })
            await self._write_run(conn, updated)
            await conn.execute("UPDATE worker_leases SET lease_expires_at=$1 WHERE run_id=$2", now, run_id)
            await self._append_event(conn, AuditEvent(
                run_id=run_id,
                event_type=(
                    "simulation.cancelled" if target is SimulationRunStatus.CANCELLED
                    else "simulation.rejected" if rejected
                    else "simulation.poisoned" if error_code == "MAX_ATTEMPTS_EXCEEDED"
                    else "simulation.failed"
                ),
                actor=f"worker:{owner_id}",
                status="cancelled" if target is SimulationRunStatus.CANCELLED else "rejected" if rejected else "failed",
                metadata={} if rejected or target is SimulationRunStatus.CANCELLED else {"error_code": error_code},
            ))
            return updated

    async def request_cancellation(self, run_id: UUID, actor: str) -> SimulationRun:
        if not actor.strip() or len(actor) > 128:
            raise ValueError("Cancellation actor is invalid")
        now = self._now()
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow("SELECT payload FROM simulation_runs WHERE run_id=$1 FOR UPDATE", run_id)
            if row is None:
                raise OperationalStoreError("Simulation run does not exist")
            run = SimulationRun.model_validate_json(str(row["payload"]))
            if run.status is SimulationRunStatus.CANCELLED:
                return run
            if run.status in SimulationRunStateMachine.TERMINAL:
                raise OperationalStoreError("Terminal simulation run cannot be cancelled")
            status: SimulationRunStatus = run.status
            if status in {SimulationRunStatus.CREATED, SimulationRunStatus.WAITING_APPROVAL}:
                SimulationRunStateMachine.require(status, SimulationRunStatus.CANCELLED)
                status = SimulationRunStatus.CANCELLED
            updated = run.model_copy(update={
                "status": status, "cancellation_requested": True, "cancellation_requested_at": now,
                "cancellation_actor": actor, "updated_at": now,
            })
            await self._write_run(conn, updated)
            await self._append_event(conn, AuditEvent(
                run_id=run_id,
                event_type="simulation.cancelled" if status is SimulationRunStatus.CANCELLED else "simulation.cancel_requested",
                actor=actor, status="cancelled" if status is SimulationRunStatus.CANCELLED else "pending",
            ))
            return updated

    async def cancel_execution(self, run_id: UUID, owner_id: str, fencing_token: int) -> SimulationRun:
        now = self._now()
        async with self._pool.acquire() as conn, conn.transaction():
            run = await self._owned_run(conn, run_id, owner_id, fencing_token)
            if not run.cancellation_requested:
                raise OperationalStoreError("Simulation cancellation was not requested")
            SimulationRunStateMachine.require(run.status, SimulationRunStatus.CANCELLED)
            updated = run.model_copy(update={"status": SimulationRunStatus.CANCELLED, "updated_at": now})
            await self._write_run(conn, updated)
            await conn.execute("UPDATE worker_leases SET lease_expires_at=$1 WHERE run_id=$2", now, run_id)
            await self._append_event(conn, AuditEvent(
                run_id=run_id, event_type="simulation.cancelled", actor=f"worker:{owner_id}",
                status="cancelled", metadata={"fencing_token": str(fencing_token)},
            ))
            return updated

    # ---- immutable artifacts -----------------------------------------------------------

    async def get_result(self, run_id: UUID) -> SimulationArtifacts:
        async with self._pool.acquire() as conn:
            payload = await conn.fetchval("SELECT payload FROM simulation_results WHERE run_id=$1", run_id)
        if payload is None:
            raise OperationalStoreError("Simulation result does not exist")
        return SimulationArtifacts.model_validate_json(str(payload))

    async def get_review(self, run_id: UUID) -> SimulationReview:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT payload,checksum FROM simulation_reviews WHERE run_id=$1", run_id)
        if row is None:
            raise OperationalStoreError("Simulation review does not exist")
        payload = str(row["payload"])
        if not hmac.compare_digest(hashlib.sha256(payload.encode("utf-8")).hexdigest(), str(row["checksum"])):
            raise OperationalStoreError("Simulation review integrity check failed")
        return SimulationReview.model_validate_json(payload)

    # ---- retention purge (RetentionPurgeStore; see art_sim.retention.job) --------------

    async def purge_expired_runs(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete terminal runs (and every dependent row) last updated before ``older_than``."""
        terminal = [status.value for status in SimulationRunStateMachine.TERMINAL]
        async with self._pool.acquire() as conn, conn.transaction():
            rows = await conn.fetch(
                "SELECT run_id FROM simulation_runs WHERE status = ANY($1::text[]) "
                "AND updated_at < $2 FOR UPDATE SKIP LOCKED",
                terminal, older_than,
            )
            run_ids = [row["run_id"] for row in rows]
            if dry_run or not run_ids:
                return len(run_ids)
            for table in (
                "simulation_reviews",
                "simulation_results",
                "workflow_checkpoints",
                "worker_leases",
                "audit_events",
                "api_idempotency",
            ):
                await conn.execute(f"DELETE FROM {table} WHERE run_id = ANY($1::uuid[])", run_ids)
            await conn.execute("DELETE FROM simulation_runs WHERE run_id = ANY($1::uuid[])", run_ids)
            return len(run_ids)

    async def purge_expired_checkpoints(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete checkpoints of terminal runs created before ``older_than``."""
        terminal = [status.value for status in SimulationRunStateMachine.TERMINAL]
        async with self._pool.acquire() as conn, conn.transaction():
            rows = await conn.fetch(
                "SELECT wc.run_id FROM workflow_checkpoints wc "
                "JOIN simulation_runs sr ON sr.run_id = wc.run_id "
                "WHERE sr.status = ANY($1::text[]) AND wc.created_at < $2 FOR UPDATE OF wc SKIP LOCKED",
                terminal, older_than,
            )
            run_ids = [row["run_id"] for row in rows]
            if dry_run or not run_ids:
                return len(run_ids)
            await conn.execute("DELETE FROM workflow_checkpoints WHERE run_id = ANY($1::uuid[])", run_ids)
            return len(run_ids)

    async def purge_expired_results(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete result artifacts of terminal runs created before ``older_than``."""
        terminal = [status.value for status in SimulationRunStateMachine.TERMINAL]
        async with self._pool.acquire() as conn, conn.transaction():
            rows = await conn.fetch(
                "SELECT res.run_id FROM simulation_results res "
                "JOIN simulation_runs sr ON sr.run_id = res.run_id "
                "WHERE sr.status = ANY($1::text[]) AND res.created_at < $2 FOR UPDATE OF res SKIP LOCKED",
                terminal, older_than,
            )
            run_ids = [row["run_id"] for row in rows]
            if dry_run or not run_ids:
                return len(run_ids)
            await conn.execute("DELETE FROM simulation_results WHERE run_id = ANY($1::uuid[])", run_ids)
            return len(run_ids)

    # ---- lifecycle ---------------------------------------------------------------------

    async def health_check(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.fetchval("SELECT 1")

    async def close(self) -> None:
        await self._pool.close()

    # ---- helpers -----------------------------------------------------------------------

    async def _locked_run(self, conn: Any, run_id: UUID) -> SimulationRun:
        payload = await conn.fetchval("SELECT payload FROM simulation_runs WHERE run_id=$1 FOR UPDATE", run_id)
        if payload is None:
            raise OperationalStoreError("Simulation run does not exist")
        return SimulationRun.model_validate_json(str(payload))

    async def _owned_run(self, conn: Any, run_id: UUID, owner_id: str, fencing_token: int) -> SimulationRun:
        row = await conn.fetchrow(
            """SELECT r.payload,l.owner_id,l.fencing_token,l.lease_expires_at
               FROM simulation_runs r JOIN worker_leases l ON l.run_id=r.run_id
               WHERE r.run_id=$1 FOR UPDATE OF r""",
            run_id,
        )
        now = self._now()
        if (
            row is None
            or row["owner_id"] != owner_id
            or int(row["fencing_token"]) != fencing_token
            or row["lease_expires_at"] <= now
        ):
            raise OperationalStoreError("Worker does not own this simulation run")
        return SimulationRun.model_validate_json(str(row["payload"]))

    @staticmethod
    async def _write_run(conn: Any, run: SimulationRun) -> None:
        await conn.execute(
            "UPDATE simulation_runs SET payload=$1,status=$2,approval_status=$3,updated_at=$4 WHERE run_id=$5",
            run.model_dump_json(), run.status.value, run.approval_status.value, run.updated_at, run.run_id,
        )

    @staticmethod
    async def _append_event(conn: Any, event: AuditEvent) -> None:
        await conn.execute(
            "INSERT INTO audit_events(event_id,run_id,payload) VALUES($1,$2,$3)",
            event.event_id, event.run_id, event.model_dump_json(),
        )
