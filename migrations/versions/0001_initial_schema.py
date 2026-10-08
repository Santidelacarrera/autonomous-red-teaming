"""Initial operational schema, matching PostgresOperationalStore._SCHEMA.

This revision is written as idempotent ``CREATE TABLE IF NOT EXISTS`` so that running it
against a database the application already initialized via ``PostgresOperationalStore
.initialize()`` (the pre-migration bootstrap path, still used by tests and first-run
convenience) is a safe no-op. Every later revision is a normal, non-idempotent, reviewed
``ALTER``/``CREATE`` change.

Revision ID: 0001
Revises:
Create Date: 2026-10-08
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_CREATE = """
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

_TABLES_NEWEST_FIRST = (
    "simulation_reviews",
    "simulation_results",
    "worker_leases",
    "api_idempotency",
    "audit_events",
    "workflow_checkpoints",
    "simulation_runs",
)


def upgrade() -> None:
    op.execute(_CREATE)


def downgrade() -> None:
    # Destructive; only used to tear down an isolated/disposable environment (see
    # docs/disaster-recovery.md's controlled drill procedure). Never run against a
    # database holding live runs.
    for table in _TABLES_NEWEST_FIRST:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
