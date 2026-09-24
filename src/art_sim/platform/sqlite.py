"""SQLite-backed durable operational store using short transactional operations only."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from art_sim.domain.exceptions import ApprovalRequiredError, ConfigurationError, GraphEngineError
from art_sim.platform.models import (
    AuditEvent,
    SimulationRun,
    SimulationRunStatus,
    WorkflowCheckpoint,
)
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus


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

    _SCHEMA_VERSION = 1

    def __init__(self, database_path: Path) -> None:
        """Validate the explicit database target; it is never inferred from a secret."""
        if database_path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
            raise ConfigurationError("Operational SQLite database must use a database file extension")
        self._path = database_path

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

    async def list_events(self, run_id: UUID) -> tuple[AuditEvent, ...]:
        """Return audit events in append sequence order."""
        return await asyncio.to_thread(self._list_events_sync, run_id)

    async def decide(self, run_id: UUID, decision: ApprovalDecision, actor: str) -> SimulationRun:
        """Use one SQLite transaction as distributed compare-and-set for a waiting run."""
        if not actor.strip():
            raise ApprovalRequiredError("Approval actor is required")
        return await asyncio.to_thread(self._decide_sync, run_id, decision, actor)

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
                """
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
        if run.status in {SimulationRunStatus.COMPLETED, SimulationRunStatus.FAILED, SimulationRunStatus.REJECTED}:
            raise OperationalStoreError("Terminal simulation runs cannot be updated")
        updated = run.model_copy(update={"status": status, "updated_at": datetime.now(UTC)})
        with self._connection() as connection:
            connection.execute("UPDATE simulation_runs SET payload=?,status=?,updated_at=? WHERE run_id=?", (self._dump(updated), status.value, updated.updated_at.isoformat(), str(run_id)))
        return updated

    def _append_event_sync(self, event: AuditEvent) -> None:
        with self._connection() as connection:
            self._append_event(connection, event)

    def _list_events_sync(self, run_id: UUID) -> tuple[AuditEvent, ...]:
        with self._connection() as connection:
            rows = connection.execute("SELECT payload FROM audit_events WHERE run_id=? ORDER BY sequence", (str(run_id),)).fetchall()
        return tuple(AuditEvent.model_validate_json(str(row["payload"])) for row in rows)

    def _decide_sync(self, run_id: UUID, decision: ApprovalDecision, actor: str) -> SimulationRun:
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
            status = SimulationRunStatus.RUNNING if approval_status is ApprovalStatus.APPROVED else SimulationRunStatus.REJECTED
            now = datetime.now(UTC)
            updated = run.model_copy(update={"approval_status": approval_status, "approval_timestamp": now, "status": status, "updated_at": now})
            connection.execute("UPDATE simulation_runs SET payload=?,status=?,approval_status=?,updated_at=? WHERE run_id=?", (self._dump(updated), status.value, approval_status.value, now.isoformat(), str(run_id)))
            self._append_event(connection, AuditEvent(run_id=run_id, event_type=f"approval.{decision.value}", actor=actor, status="succeeded" if decision is ApprovalDecision.APPROVED else "rejected"))
            connection.commit()
            return updated

    @staticmethod
    def _append_event(connection: sqlite3.Connection, event: AuditEvent) -> None:
        connection.execute("INSERT INTO audit_events(event_id,run_id,payload) VALUES(?,?,?)", (str(event.event_id), str(event.run_id), SqliteOperationalStore._dump(event)))

    @staticmethod
    def _dump(model: AuditEvent | SimulationRun | WorkflowCheckpoint) -> str:
        try:
            return model.model_dump_json()
        except ValueError as error:
            raise ConfigurationError("Operational record is not JSON serializable") from error
