"""SQLite-backed durable operational store using short transactional operations only."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar
from uuid import UUID

from art_sim.domain.exceptions import ApprovalRequiredError, ConfigurationError, GraphEngineError
from art_sim.platform.lifecycle import SimulationRunStateMachine
from art_sim.platform.models import (
    AuditEvent,
    ExecutionClaim,
    SimulationRun,
    SimulationRunStatus,
    WorkflowCheckpoint,
)
from art_sim.platform.ports import OperationalStoreCapability
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus
from art_sim.worker.models import SimulationArtifacts, SimulationReview


class CheckpointCorruptionError(GraphEngineError):
    """Raised when persisted checkpoint bytes fail integrity or schema validation."""


class OperationalStoreError(GraphEngineError):
    """Raised when durable operational storage cannot safely complete an operation."""


class SqliteOperationalStore:
    """Single-file durable store for checkpoints, runs, audit evidence, and approval CAS.

    SQLite WAL transactions are sufficient for a single-node deployment and shared
    filesystem only when that filesystem provides correct SQLite locking. Multi-region
    deployment requires a server database adapter implementing the same ports.
    """

    _SCHEMA_VERSION = 3
    deployment_capability: ClassVar[OperationalStoreCapability] = (
        OperationalStoreCapability.SINGLE_NODE
    )

    def __init__(
        self,
        database_path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Validate the explicit database target; it is never inferred from a secret."""
        if database_path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
            raise ConfigurationError("Operational SQLite database must use a database file extension")
        self._path = database_path
        self._clock = clock or (lambda: datetime.now(UTC))

    async def initialize(self) -> None:
        """Create versioned schema idempotently before accepting any work."""
        await asyncio.to_thread(self._initialize_sync)

    async def save_checkpoint(self, checkpoint: WorkflowCheckpoint) -> None:
        """Atomically replace a run checkpoint after validating JSON-only state."""
        await asyncio.to_thread(self._save_checkpoint_sync, checkpoint)

    async def load_checkpoint(self, run_id: UUID) -> WorkflowCheckpoint:
        """Load a checkpoint or fail closed on missing, tampered, or invalid data."""
        return await asyncio.to_thread(self._load_checkpoint_sync, run_id)

    async def create_run(self, run: SimulationRun) -> None:
        """Insert a globally unique run record and append creation evidence."""
        await asyncio.to_thread(self._create_run_sync, run)

    async def create_run_idempotent(self, run: SimulationRun, idempotency_key: str) -> tuple[SimulationRun, bool]:
        """Create once per durable API key or return its original run without duplication."""
        if not 8 <= len(idempotency_key) <= 128 or not idempotency_key.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Idempotency key is invalid")
        return await asyncio.to_thread(self._create_run_idempotent_sync, run, idempotency_key)

    async def get_run(self, run_id: UUID) -> SimulationRun:
        """Return one current run record or a clear missing-record error."""
        return await asyncio.to_thread(self._get_run_sync, run_id)

    async def list_runs(
        self, *, limit: int = 50, offset: int = 0, status: SimulationRunStatus | None = None
    ) -> tuple[SimulationRun, ...]:
        """List bounded current run records for API pagination without unbounded scans."""
        if not 1 <= limit <= 200 or offset < 0:
            raise ValueError("limit must be 1..200 and offset must not be negative")
        return await asyncio.to_thread(self._list_runs_sync, limit, offset, status)

    async def update_status(self, run_id: UUID, status: SimulationRunStatus) -> SimulationRun:
        """Update non-approval status while preserving the immutable audit trail."""
        return await asyncio.to_thread(self._update_status_sync, run_id, status)

    async def append_event(self, event: AuditEvent) -> None:
        """Append an event only; existing events are never updated or deleted."""
        await asyncio.to_thread(self._append_event_sync, event)

    async def append_worker_event(
        self,
        event: AuditEvent,
        owner_id: str,
        fencing_token: int,
    ) -> None:
        """Append worker evidence only while the exact fenced lease remains live."""
        await asyncio.to_thread(
            self._append_worker_event_sync,
            event,
            owner_id,
            fencing_token,
        )

    async def list_events(self, run_id: UUID) -> tuple[AuditEvent, ...]:
        """Return audit events in append sequence order."""
        return await asyncio.to_thread(self._list_events_sync, run_id)

    async def decide(
        self,
        run_id: UUID,
        decision: ApprovalDecision,
        actor: str,
        reason: str = "Reviewed through a trusted internal coordinator.",
    ) -> SimulationRun:
        """Use one SQLite transaction as distributed compare-and-set for a waiting run."""
        if not actor.strip():
            raise ApprovalRequiredError("Approval actor is required")
        if not 10 <= len(reason.strip()) <= 512:
            raise ApprovalRequiredError("Approval reason must contain 10 to 512 characters")
        return await asyncio.to_thread(
            self._decide_sync,
            run_id,
            decision,
            actor,
            reason.strip(),
        )

    async def acquire_execution(
        self,
        run_id: UUID,
        owner_id: str,
        trace_id: UUID,
        *,
        lease_seconds: int = 300,
        expected_attempt: int | None = None,
    ) -> ExecutionClaim | None:
        """Atomically acquire one run across workers and transition it into execution."""
        if not owner_id or len(owner_id) > 128 or lease_seconds < 1:
            raise ValueError("Worker ownership parameters are invalid")
        return await asyncio.to_thread(
            self._acquire_execution_sync,
            run_id,
            owner_id,
            trace_id,
            lease_seconds,
            expected_attempt,
        )

    async def next_execution_attempt(self, run_id: UUID) -> int:
        """Return the next fencing generation without mutating ownership."""
        return await asyncio.to_thread(self._next_execution_attempt_sync, run_id)

    async def renew_execution(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        *,
        lease_seconds: int = 300,
    ) -> bool:
        """Extend only a live lease owned by the exact fencing generation."""
        return await asyncio.to_thread(
            self._renew_execution_sync,
            run_id,
            owner_id,
            fencing_token,
            lease_seconds,
        )

    async def release_execution(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
    ) -> None:
        """Expire a live lease so another worker can recover it safely."""
        await asyncio.to_thread(
            self._release_execution_sync,
            run_id,
            owner_id,
            fencing_token,
        )

    async def mark_waiting_approval(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        review: SimulationReview | None = None,
    ) -> SimulationRun:
        """Persist the HITL boundary and relinquish execution ownership atomically."""
        return await asyncio.to_thread(
            self._mark_waiting_approval_sync,
            run_id,
            owner_id,
            fencing_token,
            review,
        )

    async def complete_execution(
        self,
        artifacts: SimulationArtifacts,
        owner_id: str,
        fencing_token: int,
    ) -> SimulationRun:
        """Commit immutable results and terminal success in one transaction."""
        return await asyncio.to_thread(
            self._complete_execution_sync,
            artifacts,
            owner_id,
            fencing_token,
        )

    async def reject_execution(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
    ) -> SimulationRun:
        """Finalize an HMAC-processed rejection without producing result artifacts."""
        return await asyncio.to_thread(
            self._finish_without_result_sync,
            run_id,
            owner_id,
            fencing_token,
            True,
        )

    async def fail_execution(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        error_code: str,
    ) -> SimulationRun:
        """Persist only a bounded safe error code and release worker ownership."""
        if not error_code or len(error_code) > 64 or not error_code.replace("_", "").isalnum():
            raise ValueError("Worker error code is invalid")
        return await asyncio.to_thread(
            self._finish_without_result_sync,
            run_id,
            owner_id,
            fencing_token,
            False,
            error_code,
        )

    async def request_cancellation(self, run_id: UUID, actor: str) -> SimulationRun:
        """Atomically request cooperative cancellation or cancel an idle active run."""
        if not actor.strip() or len(actor) > 128:
            raise ValueError("Cancellation actor is invalid")
        return await asyncio.to_thread(self._request_cancellation_sync, run_id, actor)

    async def cancel_execution(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
    ) -> SimulationRun:
        """Finalize cancellation from the currently fenced worker only."""
        return await asyncio.to_thread(
            self._cancel_execution_sync,
            run_id,
            owner_id,
            fencing_token,
        )

    async def get_result(self, run_id: UUID) -> SimulationArtifacts:
        """Load one immutable final artifact bundle by run identifier."""
        return await asyncio.to_thread(self._get_result_sync, run_id)

    async def get_review(self, run_id: UUID) -> SimulationReview:
        """Load the immutable security-review package for a paused simulation."""
        return await asyncio.to_thread(self._get_review_sync, run_id)

    def _connection(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize_sync(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS simulation_runs (
                  run_id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL,
                  approval_status TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workflow_checkpoints (
                  run_id TEXT PRIMARY KEY, payload TEXT NOT NULL, checksum TEXT NOT NULL,
                  checkpoint_version INTEGER NOT NULL, created_at TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES simulation_runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                  sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
                  run_id TEXT NOT NULL, payload TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES simulation_runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS api_idempotency (
                  idempotency_key TEXT PRIMARY KEY, run_id TEXT NOT NULL, scenario_id TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES simulation_runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS worker_leases (
                  run_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, attempt INTEGER NOT NULL,
                  fencing_token INTEGER NOT NULL, acquired_at TEXT NOT NULL,
                  lease_expires_at TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES simulation_runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS simulation_results (
                  run_id TEXT PRIMARY KEY, workflow_version TEXT NOT NULL,
                  payload TEXT NOT NULL, created_at TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES simulation_runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS simulation_reviews (
                  run_id TEXT PRIMARY KEY, workflow_version TEXT NOT NULL,
                  payload TEXT NOT NULL, checksum TEXT NOT NULL, created_at TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES simulation_runs(run_id)
                );
                """
            )
            lease_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(worker_leases)").fetchall()
            }
            if "fencing_token" not in lease_columns:
                connection.execute(
                    "ALTER TABLE worker_leases ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 0"
                )
                connection.execute(
                    "UPDATE worker_leases SET fencing_token=attempt WHERE fencing_token=0"
                )
            connection.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (?)", (self._SCHEMA_VERSION,))

    def _save_checkpoint_sync(self, checkpoint: WorkflowCheckpoint) -> None:
        payload = self._dump(checkpoint)
        checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self._connection() as connection:
            if connection.execute("SELECT 1 FROM simulation_runs WHERE run_id = ?", (str(checkpoint.run_id),)).fetchone() is None:
                raise OperationalStoreError("Cannot checkpoint an unknown simulation run")
            connection.execute(
                """INSERT INTO workflow_checkpoints(run_id,payload,checksum,checkpoint_version,created_at)
                   VALUES(?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET payload=excluded.payload,
                   checksum=excluded.checksum,checkpoint_version=excluded.checkpoint_version,created_at=excluded.created_at""",
                (str(checkpoint.run_id), payload, checksum, checkpoint.checkpoint_version, checkpoint.created_at.isoformat()),
            )

    def _load_checkpoint_sync(self, run_id: UUID) -> WorkflowCheckpoint:
        with self._connection() as connection:
            row = connection.execute("SELECT payload,checksum FROM workflow_checkpoints WHERE run_id = ?", (str(run_id),)).fetchone()
        if row is None:
            raise OperationalStoreError("Checkpoint does not exist")
        payload = str(row["payload"])
        if not hmac.compare_digest(hashlib.sha256(payload.encode("utf-8")).hexdigest(), str(row["checksum"])):
            raise CheckpointCorruptionError("Checkpoint integrity verification failed")
        try:
            return WorkflowCheckpoint.model_validate_json(payload)
        except ValueError as error:
            raise CheckpointCorruptionError("Checkpoint schema validation failed") from error

    def _create_run_sync(self, run: SimulationRun) -> None:
        payload = self._dump(run)
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO simulation_runs(run_id,payload,status,approval_status,updated_at) VALUES(?,?,?,?,?)",
                    (str(run.run_id), payload, run.status.value, run.approval_status.value, run.updated_at.isoformat()),
                )
                self._append_event(connection, AuditEvent(run_id=run.run_id, event_type="simulation.created", actor=run.created_by, status="pending"))
                connection.commit()
            except sqlite3.IntegrityError as error:
                connection.rollback()
                raise OperationalStoreError("Simulation run already exists") from error

    def _create_run_idempotent_sync(self, run: SimulationRun, idempotency_key: str) -> tuple[SimulationRun, bool]:
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute("SELECT run_id,scenario_id FROM api_idempotency WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                if existing is not None:
                    if existing["scenario_id"] != run.scenario_id:
                        connection.rollback()
                        raise OperationalStoreError("Idempotency key was already used for another scenario")
                    payload = connection.execute("SELECT payload FROM simulation_runs WHERE run_id=?", (existing["run_id"],)).fetchone()
                    if payload is None:
                        connection.rollback()
                        raise OperationalStoreError("Idempotency record references an unavailable run")
                    connection.commit()
                    return SimulationRun.model_validate_json(str(payload["payload"])), False
                connection.execute("INSERT INTO simulation_runs(run_id,payload,status,approval_status,updated_at) VALUES(?,?,?,?,?)", (str(run.run_id), self._dump(run), run.status.value, run.approval_status.value, run.updated_at.isoformat()))
                connection.execute("INSERT INTO api_idempotency(idempotency_key,run_id,scenario_id) VALUES(?,?,?)", (idempotency_key, str(run.run_id), run.scenario_id))
                self._append_event(connection, AuditEvent(run_id=run.run_id, event_type="simulation.created", actor=run.created_by, status="pending"))
                connection.commit()
                return run, True
            except sqlite3.IntegrityError as error:
                connection.rollback()
                raise OperationalStoreError("Simulation run could not be created") from error

    def _get_run_sync(self, run_id: UUID) -> SimulationRun:
        with self._connection() as connection:
            row = connection.execute("SELECT payload FROM simulation_runs WHERE run_id = ?", (str(run_id),)).fetchone()
        if row is None:
            raise OperationalStoreError("Simulation run does not exist")
        return SimulationRun.model_validate_json(str(row["payload"]))

    def _list_runs_sync(
        self, limit: int, offset: int, status: SimulationRunStatus | None
    ) -> tuple[SimulationRun, ...]:
        query = "SELECT payload FROM simulation_runs"
        parameters: tuple[object, ...] = ()
        if status is not None:
            query += " WHERE status=?"
            parameters = (status.value,)
        query += " ORDER BY updated_at DESC, run_id DESC LIMIT ? OFFSET ?"
        with self._connection() as connection:
            rows = connection.execute(query, (*parameters, limit, offset)).fetchall()
        return tuple(SimulationRun.model_validate_json(str(row["payload"])) for row in rows)

    def _update_status_sync(self, run_id: UUID, status: SimulationRunStatus) -> SimulationRun:
        run = self._get_run_sync(run_id)
        if run.status in SimulationRunStateMachine.TERMINAL:
            raise OperationalStoreError("Terminal simulation runs cannot be updated")
        SimulationRunStateMachine.require(run.status, status)
        updated = run.model_copy(update={"status": status, "updated_at": datetime.now(UTC)})
        with self._connection() as connection:
            connection.execute("UPDATE simulation_runs SET payload=?,status=?,updated_at=? WHERE run_id=?", (self._dump(updated), status.value, updated.updated_at.isoformat(), str(run_id)))
        return updated

    def _append_event_sync(self, event: AuditEvent) -> None:
        with self._connection() as connection:
            self._append_event(connection, event)

    def _append_worker_event_sync(
        self,
        event: AuditEvent,
        owner_id: str,
        fencing_token: int,
    ) -> None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._owned_run(connection, event.run_id, owner_id, fencing_token)
            self._append_event(connection, event)
            connection.commit()

    def _list_events_sync(self, run_id: UUID) -> tuple[AuditEvent, ...]:
        with self._connection() as connection:
            rows = connection.execute("SELECT payload FROM audit_events WHERE run_id=? ORDER BY sequence", (str(run_id),)).fetchall()
        return tuple(AuditEvent.model_validate_json(str(row["payload"])) for row in rows)

    def _decide_sync(
        self,
        run_id: UUID,
        decision: ApprovalDecision,
        actor: str,
        reason: str,
    ) -> SimulationRun:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload,status,approval_status FROM simulation_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if row is None:
                connection.rollback()
                raise OperationalStoreError("Simulation run does not exist")
            if row["status"] != SimulationRunStatus.WAITING_APPROVAL.value or row["approval_status"] != ApprovalStatus.PENDING.value:
                connection.rollback()
                raise ApprovalRequiredError("Only a pending waiting run can receive a decision")
            run = SimulationRun.model_validate_json(str(row["payload"]))
            approval_status = ApprovalStatus.APPROVED if decision is ApprovalDecision.APPROVED else ApprovalStatus.REJECTED
            status = SimulationRunStatus.RESUMING
            SimulationRunStateMachine.require(run.status, status)
            now = datetime.now(UTC)
            updated = run.model_copy(
                update={
                    "approval_status": approval_status,
                    "approval_timestamp": now,
                    "approval_actor": actor,
                    "approval_reason": reason,
                    "status": status,
                    "updated_at": now,
                }
            )
            connection.execute("UPDATE simulation_runs SET payload=?,status=?,approval_status=?,updated_at=? WHERE run_id=?", (self._dump(updated), status.value, approval_status.value, now.isoformat(), str(run_id)))
            self._append_event(
                connection,
                AuditEvent(
                    run_id=run_id,
                    event_type=f"simulation.{decision.value}",
                    actor=actor,
                    status=(
                        "succeeded"
                        if decision is ApprovalDecision.APPROVED
                        else "rejected"
                    ),
                ),
            )
            connection.commit()
            return updated

    def _acquire_execution_sync(
        self,
        run_id: UUID,
        owner_id: str,
        trace_id: UUID,
        lease_seconds: int,
        expected_attempt: int | None,
    ) -> ExecutionClaim | None:
        now = self._clock()
        if now.tzinfo is None:
            raise ConfigurationError("Operational store clock must be timezone-aware")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM simulation_runs WHERE run_id=?",
                (str(run_id),),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise OperationalStoreError("Simulation run does not exist")
            run = SimulationRun.model_validate_json(str(row["payload"]))
            if run.status not in {
                SimulationRunStatus.CREATED,
                SimulationRunStatus.RUNNING,
                SimulationRunStatus.RESUMING,
            }:
                connection.rollback()
                return None
            lease = connection.execute(
                """SELECT attempt,fencing_token,lease_expires_at
                   FROM worker_leases WHERE run_id=?""",
                (str(run_id),),
            ).fetchone()
            if lease is not None and datetime.fromisoformat(str(lease["lease_expires_at"])) > now:
                connection.rollback()
                return None
            attempt = int(lease["attempt"]) + 1 if lease is not None else 1
            if expected_attempt is not None and expected_attempt != attempt:
                connection.rollback()
                return None
            fencing_token = int(lease["fencing_token"]) + 1 if lease is not None else 1
            original_status = run.status
            if run.status is not SimulationRunStatus.RUNNING:
                SimulationRunStateMachine.require(run.status, SimulationRunStatus.RUNNING)
            updated = run.model_copy(
                update={
                    "status": SimulationRunStatus.RUNNING,
                    "trace_id": trace_id,
                    "updated_at": now,
                }
            )
            expires_at = now + timedelta(seconds=lease_seconds)
            connection.execute(
                """INSERT INTO worker_leases(
                     run_id,owner_id,attempt,fencing_token,acquired_at,lease_expires_at
                   ) VALUES(?,?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET
                   owner_id=excluded.owner_id,attempt=excluded.attempt,
                   fencing_token=excluded.fencing_token,
                   acquired_at=excluded.acquired_at,lease_expires_at=excluded.lease_expires_at""",
                (
                    str(run_id),
                    owner_id,
                    attempt,
                    fencing_token,
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            self._write_run(connection, updated)
            self._append_event(
                connection,
                AuditEvent(
                    run_id=run_id,
                    event_type=(
                        "simulation.started"
                        if original_status is SimulationRunStatus.CREATED
                        else "simulation.resumed"
                    ),
                    actor=f"worker:{owner_id}",
                    status="succeeded",
                    metadata={
                        "trace_id": str(trace_id),
                        "attempt": str(attempt),
                        "fencing_token": str(fencing_token),
                    },
                ),
            )
            connection.commit()
            return ExecutionClaim(
                run=updated,
                owner_id=owner_id,
                attempt=attempt,
                fencing_token=fencing_token,
                lease_expires_at=expires_at,
            )

    def _next_execution_attempt_sync(self, run_id: UUID) -> int:
        with self._connection() as connection:
            run_row = connection.execute(
                "SELECT status FROM simulation_runs WHERE run_id=?",
                (str(run_id),),
            ).fetchone()
            if run_row is None:
                raise OperationalStoreError("Simulation run does not exist")
            if SimulationRunStatus(str(run_row["status"])) not in {
                SimulationRunStatus.CREATED,
                SimulationRunStatus.RUNNING,
                SimulationRunStatus.RESUMING,
            }:
                raise OperationalStoreError("Simulation run is not executable")
            lease = connection.execute(
                "SELECT attempt FROM worker_leases WHERE run_id=?",
                (str(run_id),),
            ).fetchone()
        return int(lease["attempt"]) + 1 if lease is not None else 1

    def _renew_execution_sync(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        lease_seconds: int,
    ) -> bool:
        if lease_seconds < 1:
            raise ValueError("Lease duration must be positive")
        now = self._aware_now()
        expires_at = now + timedelta(seconds=lease_seconds)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """UPDATE worker_leases SET lease_expires_at=?
                   WHERE run_id=? AND owner_id=? AND fencing_token=?
                   AND lease_expires_at>?""",
                (
                    expires_at.isoformat(),
                    str(run_id),
                    owner_id,
                    fencing_token,
                    now.isoformat(),
                ),
            )
            connection.commit()
            return cursor.rowcount == 1

    def _release_execution_sync(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
    ) -> None:
        now = self._aware_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._owned_run(connection, run_id, owner_id, fencing_token)
            connection.execute(
                """UPDATE worker_leases SET lease_expires_at=?
                   WHERE run_id=? AND owner_id=? AND fencing_token=?""",
                (now.isoformat(), str(run_id), owner_id, fencing_token),
            )
            self._append_event(
                connection,
                AuditEvent(
                    run_id=run_id,
                    event_type="simulation.lease_released",
                    actor=f"worker:{owner_id}",
                    status="pending",
                    metadata={"fencing_token": str(fencing_token)},
                ),
            )
            connection.commit()

    def _mark_waiting_approval_sync(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        review: SimulationReview | None,
    ) -> SimulationRun:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = self._owned_run(connection, run_id, owner_id, fencing_token)
            now = self._aware_now()
            target = (
                SimulationRunStatus.CANCELLED
                if run.cancellation_requested
                else SimulationRunStatus.WAITING_APPROVAL
            )
            SimulationRunStateMachine.require(run.status, target)
            if review is not None:
                if (
                    review.run_id != run_id
                    or review.scenario_id != run.scenario_id
                    or review.workflow_version != run.workflow_version
                ):
                    connection.rollback()
                    raise OperationalStoreError(
                        "Security review does not match its simulation run"
                    )
                review_payload = review.model_dump_json()
                review_checksum = hashlib.sha256(
                    review_payload.encode("utf-8")
                ).hexdigest()
                connection.execute(
                    """INSERT INTO simulation_reviews(
                           run_id,workflow_version,payload,checksum,created_at
                       ) VALUES(?,?,?,?,?)""",
                    (
                        str(run_id),
                        review.workflow_version,
                        review_payload,
                        review_checksum,
                        review.generated_at.isoformat(),
                    ),
                )
            updated = run.model_copy(
                update={
                    "status": target,
                    "review_ready": review is not None,
                    "updated_at": now,
                }
            )
            self._write_run(connection, updated)
            connection.execute(
                "UPDATE worker_leases SET lease_expires_at=? WHERE run_id=?",
                (now.isoformat(), str(run_id)),
            )
            self._append_event(
                connection,
                AuditEvent(
                    run_id=run_id,
                    event_type=(
                        "simulation.cancelled"
                        if target is SimulationRunStatus.CANCELLED
                        else "simulation.waiting_approval"
                    ),
                    actor=f"worker:{owner_id}",
                    status=(
                        "cancelled"
                        if target is SimulationRunStatus.CANCELLED
                        else "pending"
                    ),
                ),
            )
            connection.commit()
            return updated

    def _complete_execution_sync(
        self,
        artifacts: SimulationArtifacts,
        owner_id: str,
        fencing_token: int,
    ) -> SimulationRun:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = self._owned_run(
                connection,
                artifacts.run_id,
                owner_id,
                fencing_token,
            )
            SimulationRunStateMachine.require(run.status, SimulationRunStatus.SUCCEEDED)
            if run.cancellation_requested:
                connection.rollback()
                raise OperationalStoreError("Cancellation prevents result publication")
            if run.workflow_version != artifacts.workflow_version or run.scenario_id != artifacts.scenario_id:
                connection.rollback()
                raise OperationalStoreError("Result artifact does not match its simulation run")
            connection.execute(
                "INSERT INTO simulation_results(run_id,workflow_version,payload,created_at) VALUES(?,?,?,?)",
                (
                    str(artifacts.run_id),
                    artifacts.workflow_version,
                    artifacts.model_dump_json(),
                    artifacts.generated_at.isoformat(),
                ),
            )
            updated = run.model_copy(
                update={
                    "status": SimulationRunStatus.SUCCEEDED,
                    "graph_version": artifacts.graph_version,
                    "risk_before": artifacts.risk.score,
                    "risk_after": artifacts.verification.risk_after,
                    "blast_radius_before": artifacts.blast_radius.blast_radius_percentage,
                    "blast_radius_after": (
                        artifacts.verification.blast_radius_after.blast_radius_percentage
                    ),
                    "verification_status": artifacts.verification.status,
                    "artifacts": tuple(
                        artifact.file_path for artifact in artifacts.remediation_artifacts
                    )
                    + ("report.md",),
                    "updated_at": self._aware_now(),
                }
            )
            self._write_run(connection, updated)
            connection.execute(
                "UPDATE worker_leases SET lease_expires_at=? WHERE run_id=?",
                (updated.updated_at.isoformat(), str(artifacts.run_id)),
            )
            self._append_event(
                connection,
                AuditEvent(
                    run_id=artifacts.run_id,
                    event_type="simulation.completed",
                    actor=f"worker:{owner_id}",
                    status="succeeded",
                    metadata={"trace_id": str(artifacts.trace_id)},
                ),
            )
            connection.commit()
            return updated

    def _finish_without_result_sync(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
        rejected: bool,
        error_code: str = "SIMULATION_REJECTED",
    ) -> SimulationRun:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = self._owned_run(connection, run_id, owner_id, fencing_token)
            target = (
                SimulationRunStatus.CANCELLED
                if run.cancellation_requested
                else SimulationRunStatus.REJECTED
                if rejected
                else SimulationRunStatus.FAILED
            )
            SimulationRunStateMachine.require(run.status, target)
            now = self._aware_now()
            updated = run.model_copy(
                update={
                    "status": target,
                    "error_code": (
                        None
                        if rejected or target is SimulationRunStatus.CANCELLED
                        else error_code
                    ),
                    "updated_at": now,
                }
            )
            self._write_run(connection, updated)
            connection.execute(
                "UPDATE worker_leases SET lease_expires_at=? WHERE run_id=?",
                (now.isoformat(), str(run_id)),
            )
            self._append_event(
                connection,
                AuditEvent(
                    run_id=run_id,
                    event_type=(
                        "simulation.cancelled"
                        if target is SimulationRunStatus.CANCELLED
                        else "simulation.rejected"
                        if rejected
                        else "simulation.poisoned"
                        if error_code == "MAX_ATTEMPTS_EXCEEDED"
                        else "simulation.failed"
                    ),
                    actor=f"worker:{owner_id}",
                    status=(
                        "cancelled"
                        if target is SimulationRunStatus.CANCELLED
                        else "rejected"
                        if rejected
                        else "failed"
                    ),
                    metadata=(
                        {}
                        if rejected or target is SimulationRunStatus.CANCELLED
                        else {"error_code": error_code}
                    ),
                ),
            )
            connection.commit()
            return updated

    def _request_cancellation_sync(self, run_id: UUID, actor: str) -> SimulationRun:
        now = self._aware_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM simulation_runs WHERE run_id=?",
                (str(run_id),),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise OperationalStoreError("Simulation run does not exist")
            run = SimulationRun.model_validate_json(str(row["payload"]))
            if run.status is SimulationRunStatus.CANCELLED:
                connection.commit()
                return run
            if run.status in SimulationRunStateMachine.TERMINAL:
                connection.rollback()
                raise OperationalStoreError("Terminal simulation run cannot be cancelled")
            status: SimulationRunStatus = run.status
            if status in {
                SimulationRunStatus.CREATED,
                SimulationRunStatus.WAITING_APPROVAL,
            }:
                SimulationRunStateMachine.require(status, SimulationRunStatus.CANCELLED)
                status = SimulationRunStatus.CANCELLED
            updated = run.model_copy(
                update={
                    "status": status,
                    "cancellation_requested": True,
                    "cancellation_requested_at": now,
                    "cancellation_actor": actor,
                    "updated_at": now,
                }
            )
            self._write_run(connection, updated)
            self._append_event(
                connection,
                AuditEvent(
                    run_id=run_id,
                    event_type=(
                        "simulation.cancelled"
                        if status is SimulationRunStatus.CANCELLED
                        else "simulation.cancel_requested"
                    ),
                    actor=actor,
                    status=(
                        "cancelled"
                        if status is SimulationRunStatus.CANCELLED
                        else "pending"
                    ),
                ),
            )
            connection.commit()
            return updated

    def _cancel_execution_sync(
        self,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
    ) -> SimulationRun:
        now = self._aware_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = self._owned_run(connection, run_id, owner_id, fencing_token)
            if not run.cancellation_requested:
                connection.rollback()
                raise OperationalStoreError("Simulation cancellation was not requested")
            SimulationRunStateMachine.require(run.status, SimulationRunStatus.CANCELLED)
            updated = run.model_copy(
                update={"status": SimulationRunStatus.CANCELLED, "updated_at": now}
            )
            self._write_run(connection, updated)
            connection.execute(
                "UPDATE worker_leases SET lease_expires_at=? WHERE run_id=?",
                (now.isoformat(), str(run_id)),
            )
            self._append_event(
                connection,
                AuditEvent(
                    run_id=run_id,
                    event_type="simulation.cancelled",
                    actor=f"worker:{owner_id}",
                    status="cancelled",
                    metadata={"fencing_token": str(fencing_token)},
                ),
            )
            connection.commit()
            return updated

    def _get_result_sync(self, run_id: UUID) -> SimulationArtifacts:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM simulation_results WHERE run_id=?",
                (str(run_id),),
            ).fetchone()
        if row is None:
            raise OperationalStoreError("Simulation result does not exist")
        return SimulationArtifacts.model_validate_json(str(row["payload"]))

    def _get_review_sync(self, run_id: UUID) -> SimulationReview:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload,checksum FROM simulation_reviews WHERE run_id=?",
                (str(run_id),),
            ).fetchone()
        if row is None:
            raise OperationalStoreError("Simulation review does not exist")
        payload = str(row["payload"])
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected, str(row["checksum"])):
            raise OperationalStoreError("Simulation review integrity check failed")
        return SimulationReview.model_validate_json(payload)

    def _owned_run(
        self,
        connection: sqlite3.Connection,
        run_id: UUID,
        owner_id: str,
        fencing_token: int,
    ) -> SimulationRun:
        row = connection.execute(
            """SELECT r.payload,l.owner_id,l.fencing_token,l.lease_expires_at
               FROM simulation_runs r
               JOIN worker_leases l ON l.run_id=r.run_id WHERE r.run_id=?""",
            (str(run_id),),
        ).fetchone()
        now = self._aware_now()
        if (
            row is None
            or row["owner_id"] != owner_id
            or int(row["fencing_token"]) != fencing_token
            or datetime.fromisoformat(str(row["lease_expires_at"])) <= now
        ):
            raise OperationalStoreError("Worker does not own this simulation run")
        return SimulationRun.model_validate_json(str(row["payload"]))

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ConfigurationError("Operational store clock must be timezone-aware")
        return now

    @staticmethod
    def _write_run(connection: sqlite3.Connection, run: SimulationRun) -> None:
        connection.execute(
            """UPDATE simulation_runs SET payload=?,status=?,approval_status=?,updated_at=?
               WHERE run_id=?""",
            (
                run.model_dump_json(),
                run.status.value,
                run.approval_status.value,
                run.updated_at.isoformat(),
                str(run.run_id),
            ),
        )

    @staticmethod
    def _append_event(connection: sqlite3.Connection, event: AuditEvent) -> None:
        connection.execute("INSERT INTO audit_events(event_id,run_id,payload) VALUES(?,?,?)", (str(event.event_id), str(event.run_id), SqliteOperationalStore._dump(event)))

    @staticmethod
    def _dump(
        model: AuditEvent | SimulationRun | WorkflowCheckpoint | SimulationArtifacts,
    ) -> str:
        try:
            return model.model_dump_json()
        except ValueError as error:
            raise ConfigurationError("Operational record is not JSON serializable") from error
