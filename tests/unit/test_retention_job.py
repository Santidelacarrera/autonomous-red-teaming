"""Unit tests for ``RetentionJob`` against fake store/broker/audit ports."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from art_sim.platform.production_config import DataRetentionSettings
from art_sim.retention.job import RetentionJob
from art_sim.security.audit import SecurityAuditEvent, SecurityEventType


class FakeRetentionStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime, bool]] = []
        self.runs_to_report = 3
        self.checkpoints_to_report = 2
        self.results_to_report = 1

    async def purge_expired_runs(self, *, older_than: datetime, dry_run: bool) -> int:
        self.calls.append(("runs", older_than, dry_run))
        return self.runs_to_report

    async def purge_expired_checkpoints(self, *, older_than: datetime, dry_run: bool) -> int:
        self.calls.append(("checkpoints", older_than, dry_run))
        return self.checkpoints_to_report

    async def purge_expired_results(self, *, older_than: datetime, dry_run: bool) -> int:
        self.calls.append(("results", older_than, dry_run))
        return self.results_to_report


class FakeRetentionBroker:
    def __init__(self) -> None:
        self.calls: list[tuple[datetime, bool]] = []
        self.dead_letter_to_report = 5

    async def purge_dead_letter(self, *, older_than: datetime, dry_run: bool) -> int:
        self.calls.append((older_than, dry_run))
        return self.dead_letter_to_report


class FakeAuditSink:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def append(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)

    async def recent(self, limit: int = 50) -> tuple[SecurityAuditEvent, ...]:
        return tuple(self.events[-limit:])


def _settings(**overrides: int) -> DataRetentionSettings:
    base = {
        "simulation_days": 90,
        "result_artifact_days": 90,
        "checkpoint_days": 30,
        "dead_letter_days": 30,
        "telemetry_days": 30,
    }
    base.update(overrides)
    return DataRetentionSettings(**base)


async def test_dry_run_reports_without_deleting() -> None:
    store = FakeRetentionStore()
    job = RetentionJob(store, _settings())
    report = await job.run(dry_run=True)
    assert report.dry_run is True
    assert report.runs_purged == 3
    assert report.checkpoints_purged == 2
    assert report.results_purged == 1
    assert report.dead_letter_purged == 0
    assert report.total_purged == 6
    assert all(call[2] is True for call in store.calls)  # every call carried dry_run=True


async def test_execute_passes_dry_run_false() -> None:
    store = FakeRetentionStore()
    job = RetentionJob(store, _settings())
    report = await job.run(dry_run=False)
    assert report.dry_run is False
    assert all(call[2] is False for call in store.calls)


async def test_cutoffs_use_configured_retention_days() -> None:
    frozen_now = datetime(2026, 1, 1, tzinfo=UTC)
    store = FakeRetentionStore()
    job = RetentionJob(
        store, _settings(simulation_days=90, checkpoint_days=30, result_artifact_days=7), clock=lambda: frozen_now
    )
    await job.run(dry_run=True)
    cutoffs = {name: older_than for name, older_than, _dry_run in store.calls}
    assert cutoffs["runs"] == frozen_now - timedelta(days=90)
    assert cutoffs["checkpoints"] == frozen_now - timedelta(days=30)
    assert cutoffs["results"] == frozen_now - timedelta(days=7)


async def test_broker_is_optional() -> None:
    store = FakeRetentionStore()
    job = RetentionJob(store, _settings())
    report = await job.run(dry_run=True)
    assert report.dead_letter_purged == 0


async def test_broker_dead_letter_purge_is_included_when_configured() -> None:
    store = FakeRetentionStore()
    broker = FakeRetentionBroker()
    job = RetentionJob(store, _settings(), broker=broker)
    report = await job.run(dry_run=True)
    assert report.dead_letter_purged == 5
    assert report.total_purged == 11
    assert broker.calls[0][1] is True


async def test_every_run_emits_an_audit_event() -> None:
    store = FakeRetentionStore()
    audit_sink = FakeAuditSink()
    job = RetentionJob(store, _settings(), audit_sink=audit_sink)
    await job.run(dry_run=True)
    assert len(audit_sink.events) == 1
    assert audit_sink.events[0].event_type == SecurityEventType.DATA_RETENTION_PURGED
    assert audit_sink.events[0].result == "succeeded"


async def test_missing_audit_sink_does_not_fail_the_run() -> None:
    store = FakeRetentionStore()
    job = RetentionJob(store, _settings(), audit_sink=None)
    report = await job.run(dry_run=True)
    assert report.total_purged == 6


async def test_report_total_purged_sums_every_category() -> None:
    store = FakeRetentionStore()
    store.runs_to_report = 10
    store.checkpoints_to_report = 20
    store.results_to_report = 30
    job = RetentionJob(store, _settings())
    report = await job.run(dry_run=True)
    assert report.total_purged == 60


@pytest.mark.parametrize("field", ["runs_purged", "checkpoints_purged", "results_purged", "dead_letter_purged"])
def test_report_counts_cannot_be_negative(field: str) -> None:
    from art_sim.retention.job import RetentionRunReport

    kwargs = {
        "executed_at": datetime.now(UTC),
        "dry_run": True,
        "runs_purged": 0,
        "checkpoints_purged": 0,
        "results_purged": 0,
        "dead_letter_purged": 0,
    }
    kwargs[field] = -1
    with pytest.raises(ValidationError):
        RetentionRunReport(**kwargs)
