"""Automated data-retention purge job — the executable counterpart to the policy table in
``docs/data-retention.md``, which previously documented retention windows
(``ART_*_RETENTION_DAYS``) that nothing actually enforced.

``RetentionJob`` applies ``DataRetentionSettings`` (the same non-secret settings object the
production composition root already validates at startup, see
``platform.production_config``) against whichever ports are injected, and reports exactly
what it deleted — or would delete, under ``dry_run=True`` — as one typed report. It never
invents a retention window: every cutoff comes from the organization's own configured
``*_RETENTION_DAYS`` value, exactly as ``docs/data-retention.md`` requires ("Retention
values are explicit deployment configuration; the repository does not infer a
jurisdiction, legal hold, privacy regime or compliance schedule").

Every run — successful or not, real or dry — is written to the security audit sink as a
``SecurityEventType.DATA_RETENTION_PURGED`` event, because a job that silently deletes
historical data without leaving its own evidence of having run would defeat the audit trail
the rest of this codebase is built around.

Telemetry retention (``ART_TELEMETRY_RETENTION_DAYS``) is deliberately not purged here: it
is backend TTL/delete-owned (the OTLP/Prometheus backend), as ``docs/data-retention.md``
already documents, and this job does not reach into that backend.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from art_sim.platform.production_config import DataRetentionSettings
from art_sim.platform.retention import RetentionPurgeBroker, RetentionPurgeStore
from art_sim.security.audit import SecurityAuditEvent, SecurityAuditSink, SecurityEventType


class RetentionRunReport(BaseModel):
    """What one retention job run deleted (or would delete, under ``dry_run``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    executed_at: datetime
    dry_run: bool
    runs_purged: int = Field(ge=0)
    checkpoints_purged: int = Field(ge=0)
    results_purged: int = Field(ge=0)
    dead_letter_purged: int = Field(ge=0)

    @property
    def total_purged(self) -> int:
        return self.runs_purged + self.checkpoints_purged + self.results_purged + self.dead_letter_purged


class RetentionJob:
    """Apply ``DataRetentionSettings`` against the injected store/broker ports."""

    def __init__(
        self,
        store: RetentionPurgeStore,
        settings: DataRetentionSettings,
        *,
        broker: RetentionPurgeBroker | None = None,
        audit_sink: SecurityAuditSink | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._broker = broker
        self._settings = settings
        self._audit_sink = audit_sink
        self._clock = clock or (lambda: datetime.now(UTC))

    def _cutoff(self, days: int) -> datetime:
        return self._clock() - timedelta(days=days)

    async def run(self, *, dry_run: bool = True) -> RetentionRunReport:
        """Purge (or, under ``dry_run``, count) every expired record class.

        Runs are not purged until *all* of their dependent rows (checkpoints, results)
        would also be in scope, because ``purge_expired_runs`` deletes a run and every
        dependent row together — running it before narrower checkpoint/result purges would
        make those look like they purged nothing, when in fact the run purge already
        covered them. The narrower purges still run afterward for the common case where a
        run is kept longer than its checkpoints/results should be.
        """
        now = self._clock()
        runs_purged = await self._store.purge_expired_runs(
            older_than=self._cutoff(self._settings.simulation_days), dry_run=dry_run
        )
        checkpoints_purged = await self._store.purge_expired_checkpoints(
            older_than=self._cutoff(self._settings.checkpoint_days), dry_run=dry_run
        )
        results_purged = await self._store.purge_expired_results(
            older_than=self._cutoff(self._settings.result_artifact_days), dry_run=dry_run
        )
        dead_letter_purged = 0
        if self._broker is not None:
            dead_letter_purged = await self._broker.purge_dead_letter(
                older_than=self._cutoff(self._settings.dead_letter_days), dry_run=dry_run
            )

        report = RetentionRunReport(
            executed_at=now,
            dry_run=dry_run,
            runs_purged=runs_purged,
            checkpoints_purged=checkpoints_purged,
            results_purged=results_purged,
            dead_letter_purged=dead_letter_purged,
        )
        await self._audit(report)
        return report

    async def _audit(self, report: RetentionRunReport) -> None:
        if self._audit_sink is None:
            return
        await self._audit_sink.append(
            SecurityAuditEvent(
                event_type=SecurityEventType.DATA_RETENTION_PURGED,
                request_id=f"retention-{report.executed_at.timestamp():.0f}",
                source="retention_job",
                result="succeeded",
            )
        )
