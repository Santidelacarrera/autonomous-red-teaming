"""Add indexes required for the automated data-retention purge job to scan efficiently.

Without these, the retention job (``art_sim.retention.job.RetentionJob``, see
``docs/data-retention.md``) would need a sequential scan of every run/result/checkpoint row
to find expired records, which does not scale and risks long lock waits on tables the API
and workers also use under ``FOR UPDATE``.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-08
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_simulation_runs_status_updated_at "
        "ON simulation_runs (status, updated_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_simulation_results_created_at "
        "ON simulation_results (created_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_workflow_checkpoints_created_at "
        "ON workflow_checkpoints (created_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_workflow_checkpoints_created_at")
    op.execute("DROP INDEX IF EXISTS ix_simulation_results_created_at")
    op.execute("DROP INDEX IF EXISTS ix_simulation_runs_status_updated_at")
