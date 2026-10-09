"""Tests for the durable JSONL security-audit sink."""

from __future__ import annotations

from pathlib import Path

import pytest

from art_sim.adapters.jsonl_audit_sink import JsonlDurableSecurityAuditSink
from art_sim.domain.exceptions import DependencyUnavailableError
from art_sim.security.audit import (
    AuditDurability,
    AuditRetentionPolicy,
    SecurityAuditEvent,
    SecurityEventType,
)

POLICY = AuditRetentionPolicy(retention_days=365, archive_after_days=90)


def _event(subject: str, result: str = "succeeded") -> SecurityAuditEvent:
    return SecurityAuditEvent(
        event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
        subject=subject,
        request_id=f"req-{subject}",
        result=result,
    )


@pytest.fixture
def sink(tmp_path: Path) -> JsonlDurableSecurityAuditSink:
    return JsonlDurableSecurityAuditSink(tmp_path / "audit" / "events.jsonl", POLICY)


def test_declares_durable_capability_and_retention(sink: JsonlDurableSecurityAuditSink) -> None:
    assert JsonlDurableSecurityAuditSink.durability is AuditDurability.DURABLE
    assert sink.retention_policy.retention_days == 365


async def test_append_persists_and_recent_returns_newest_first(
    sink: JsonlDurableSecurityAuditSink,
) -> None:
    for i in range(5):
        await sink.append(_event(f"user{i}"))
    recent = await sink.recent(limit=3)
    assert [e.subject for e in recent] == ["user4", "user3", "user2"]


async def test_events_survive_a_new_sink_instance(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = JsonlDurableSecurityAuditSink(path, POLICY)
    await first.append(_event("persisted"))
    await first.close()
    # A fresh instance over the same path sees the durably written event.
    second = JsonlDurableSecurityAuditSink(path, POLICY)
    recent = await second.recent()
    assert recent[0].subject == "persisted"


async def test_credential_shaped_subject_is_redacted_before_storage(
    sink: JsonlDurableSecurityAuditSink, tmp_path: Path
) -> None:
    await sink.append(_event("Bearer secrettoken"))
    recent = await sink.recent()
    assert recent[0].subject == "[REDACTED]"


async def test_recent_rejects_out_of_range_limit(sink: JsonlDurableSecurityAuditSink) -> None:
    with pytest.raises(ValueError, match="1..200"):
        await sink.recent(limit=0)


async def test_health_check_succeeds(sink: JsonlDurableSecurityAuditSink) -> None:
    await sink.health_check()
    await sink.close()


async def test_unwritable_path_maps_to_dependency_unavailable(tmp_path: Path) -> None:
    sink = JsonlDurableSecurityAuditSink(tmp_path / "a.jsonl", POLICY)
    # Point the sink at a path whose parent is a file, forcing an OSError on write.
    broken = tmp_path / "file"
    broken.write_text("x", encoding="utf-8")
    sink._path = broken / "nested.jsonl"
    with pytest.raises(DependencyUnavailableError):
        await sink.append(_event("x"))
