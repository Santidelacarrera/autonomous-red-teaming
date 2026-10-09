"""Data-retention purge boundary — the automated-deletion counterpart to
``docs/data-retention.md``'s table, which previously documented the policy without any
code enforcing it ("Deletion jobs and archive backends are external and not implemented").

This port is intentionally separate from ``OperationalStore``/``ServerOperationalStore``
(``platform/ports.py``): not every store adapter need support bulk retention deletion (the
SQLite development store, for instance, has no production retention obligation), and a
retention job should fail closed with a clear "this store doesn't support purging" error
rather than silently no-op if asked to purge against an adapter that doesn't implement it.

Every purge method is dry-run capable: with ``dry_run=True`` it must report exactly the
count it *would* delete without deleting anything, so an operator can review the effect of
a retention-window change before it runs for real — the same operator who configured
``DataRetentionSettings`` (``platform/production_config.py``) in the first place.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class RetentionPurgeStore(Protocol):
    """Bulk, policy-driven deletion of expired operational records.

    A conforming adapter must never delete a run that is not in a terminal state (see
    ``platform.lifecycle.SimulationRunStateMachine.TERMINAL``), and must delete a run's
    dependent rows (checkpoints, results, reviews, leases, idempotency records, operational
    audit events) in the same transaction as the run itself, so a crash mid-purge can never
    leave an orphaned dependent row referencing a deleted run.
    """

    async def purge_expired_runs(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete terminal runs (and all dependent rows) last updated before ``older_than``.

        Returns the number of runs deleted (or that would be deleted, under ``dry_run``).
        """

    async def purge_expired_checkpoints(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete checkpoints of terminal runs created before ``older_than``.

        Never deletes a checkpoint belonging to a run that can still resume.
        """

    async def purge_expired_results(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete result artifacts of terminal runs created before ``older_than``."""


class RetentionPurgeBroker(Protocol):
    """Bulk deletion of poison (dead-lettered) jobs past their investigation window."""

    async def purge_dead_letter(self, *, older_than: datetime, dry_run: bool) -> int:
        """Delete dead-lettered jobs older than ``older_than``.

        Never retains the raw job payload past this point — see ``docs/data-retention.md``
        ("Delete safe poison records after investigation; raw payload retention is
        forbidden here").
        """
