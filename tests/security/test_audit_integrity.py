"""Detection of lost, duplicated, reordered and altered audit events.

The durable audit log is hash-chained (``art_sim.security.audit_chain``). These tests build a
genuine log with the production sink, then damage it the ways real failures and attackers do,
and assert the verifier names each defect precisely — and stays quiet on a healthy log.
A second group reconciles the durable log against what a (faulty) SIEM actually received.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from art_sim.adapters.jsonl_audit_sink import JsonlDurableSecurityAuditSink
from art_sim.adapters.siem_http_audit_sink import SiemForwardAuditSink
from art_sim.security.audit import AuditRetentionPolicy, SecurityAuditEvent, SecurityEventType
from art_sim.security.audit_chain import (
    GENESIS_HASH,
    durable_event_ids,
    reconcile_event_ids,
    verify_audit_log,
)

POLICY = AuditRetentionPolicy(retention_days=365)


def _event(index: int) -> SecurityAuditEvent:
    return SecurityAuditEvent(
        event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
        subject=f"user{index}",
        request_id=f"req-{index}",
        result="succeeded",
    )


async def _log(path: Path, count: int = 6) -> list[SecurityAuditEvent]:
    sink = JsonlDurableSecurityAuditSink(path, POLICY)
    events = [_event(i) for i in range(count)]
    for event in events:
        await sink.append(event)
    return events


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------- healthy log


async def test_healthy_log_verifies_and_exposes_its_head(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path, 6)
    report = verify_audit_log(path)
    assert report.ok
    assert (report.chained_events, report.first_seq, report.last_seq) == (6, 1, 6)
    assert report.head_hash is not None and report.head_hash != GENESIS_HASH


async def test_first_link_chains_from_genesis(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path, 1)
    assert json.loads(_lines(path)[0])["prev"] == GENESIS_HASH


async def test_empty_log_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    JsonlDurableSecurityAuditSink(path, POLICY)
    assert verify_audit_log(path).ok


async def test_chain_survives_restart_and_concurrent_writers(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = JsonlDurableSecurityAuditSink(path, POLICY)
    await asyncio.gather(*(first.append(_event(i)) for i in range(40)))
    second = JsonlDurableSecurityAuditSink(path, POLICY)  # simulated process restart
    await asyncio.gather(*(second.append(_event(100 + i)) for i in range(40)))
    report = verify_audit_log(path)
    assert report.ok, report.issues
    assert (report.chained_events, report.last_seq) == (80, 80)
    assert len(set(durable_event_ids(path))) == 80


# ------------------------------------------------------------------- lost events


async def test_deleted_middle_event_is_reported_as_a_gap_and_chain_break(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path)
    lines = _lines(path)
    del lines[2]
    _write(path, lines)
    report = verify_audit_log(path)
    assert not report.ok
    assert {"gap", "chain_break"} <= report.kinds()
    assert next(i for i in report.issues if i.kind == "gap").detail == "expected seq 3, found 4"


async def test_deleted_first_event_is_detected_via_genesis_link(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path)
    _write(path, _lines(path)[1:])
    assert "chain_break" in verify_audit_log(path).kinds()


async def test_truncated_tail_is_only_visible_against_an_external_anchor(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path, 6)
    anchor = verify_audit_log(path)
    _write(path, _lines(path)[:4])  # newest two events silently removed
    assert verify_audit_log(path).ok  # honest limitation: a shorter chain is self-consistent
    report = verify_audit_log(
        path, expected_last_seq=anchor.last_seq, expected_head_hash=anchor.head_hash
    )
    assert report.kinds() == {"truncated"}


async def test_rewritten_tail_with_the_right_length_fails_the_head_anchor(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path, 4)
    anchor = verify_audit_log(path)
    # Rebuild a different, internally valid chain of the same length.
    other = tmp_path / "other.jsonl"
    await _log(other, 4)
    other.replace(path)
    report = verify_audit_log(path, expected_last_seq=4, expected_head_hash=anchor.head_hash)
    assert report.kinds() == {"head_mismatch"}


# ---------------------------------------------------------------- duplicated events


async def test_duplicated_line_is_reported_as_duplicate_seq_and_event(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path)
    lines = _lines(path)
    lines.insert(3, lines[2])
    _write(path, lines)
    report = verify_audit_log(path)
    assert {"duplicate_seq", "duplicate_event"} <= report.kinds()


async def test_replayed_event_under_a_new_sequence_is_still_a_duplicate_event(
    tmp_path: Path,
) -> None:
    """The same event_id re-appended later (a retried producer) is caught by identity."""
    path = tmp_path / "audit.jsonl"
    sink = JsonlDurableSecurityAuditSink(path, POLICY)
    event = _event(1)
    await sink.append(event)
    await sink.append(_event(2))
    await sink.append(event)  # at-least-once producer retried
    report = verify_audit_log(path)
    assert report.kinds() == {"duplicate_event"}  # chain itself is intact, identity is not
    assert report.issues[0].line == 3


# --------------------------------------------------------------- altered / reordered


async def test_edited_event_body_is_a_hash_mismatch_without_cascading(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path)
    lines = _lines(path)
    document = json.loads(lines[2])
    document["event"]["result"] = "denied"
    lines[2] = json.dumps(document, separators=(",", ":"), sort_keys=True)
    _write(path, lines)
    report = verify_audit_log(path)
    assert report.kinds() == {"hash_mismatch"}
    assert [issue.line for issue in report.issues] == [3]  # only the edited line


async def test_edit_with_recomputed_hash_breaks_the_next_link(tmp_path: Path) -> None:
    from art_sim.security.audit_chain import chain_hash

    path = tmp_path / "audit.jsonl"
    await _log(path)
    lines = _lines(path)
    document = json.loads(lines[2])
    document["event"]["subject"] = "attacker"
    document["hash"] = chain_hash(document["seq"], document["prev"], document["event"])
    lines[2] = json.dumps(document, separators=(",", ":"), sort_keys=True)
    _write(path, lines)
    report = verify_audit_log(path)
    assert report.kinds() == {"chain_break"}
    assert [issue.line for issue in report.issues] == [4]


async def test_reordered_lines_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path)
    lines = _lines(path)
    lines[2], lines[3] = lines[3], lines[2]
    _write(path, lines)
    assert {"chain_break", "out_of_order", "gap"} & verify_audit_log(path).kinds()


# ------------------------------------------------------------------- torn writes


async def test_torn_write_is_reported_isolated_and_the_chain_continues(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path, 3)
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq":4,"prev":"abc","hash":"def","event":{"event_i')  # crash mid-write

    assert verify_audit_log(path).kinds() == {"malformed"}

    restarted = JsonlDurableSecurityAuditSink(path, POLICY)
    await restarted.append(_event(9))
    report = verify_audit_log(path)
    assert report.kinds() == {"malformed"}  # the evidence of the crash is preserved...
    assert (report.chained_events, report.last_seq) == (4, 4)  # ...with no gap or break
    newest = (await restarted.recent(10))[0]
    assert newest.subject == "user9"  # readers skip the torn fragment


async def test_legacy_pre_chain_lines_are_counted_and_still_readable(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    legacy = _event(0)
    path.write_text(json.dumps(legacy.model_dump(mode="json")) + "\n", encoding="utf-8")
    sink = JsonlDurableSecurityAuditSink(path, POLICY)
    await sink.append(_event(1))
    report = verify_audit_log(path)
    assert (report.legacy_events, report.chained_events) == (1, 1)
    assert report.ok
    assert [e.subject for e in await sink.recent(10)] == ["user1", "user0"]


@pytest.mark.parametrize("garbage", ["not json", "[1,2,3]", '{"seq":"x","prev":1,"hash":2,"event":{}}'])
async def test_garbage_lines_are_malformed_not_crashes(tmp_path: Path, garbage: str) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path, 2)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(garbage + "\n")
    assert "malformed" in verify_audit_log(path).kinds()


# --------------------------------------------------------------- SIEM reconciliation


def test_reconciliation_names_missing_duplicated_and_unexpected_events() -> None:
    report = reconcile_event_ids(["a", "b", "c", "d"], ["a", "a", "b", "z"])
    assert report.missing == {"c", "d"}
    assert report.duplicated == {"a"}
    assert report.unexpected == {"z"}
    assert not report.ok


def test_reconciliation_of_an_exact_stream_is_clean() -> None:
    assert reconcile_event_ids(["a", "b"], ["b", "a"]).ok


class _FlakySiem:
    """Fake SIEM endpoint that silently loses some deliveries and double-delivers others."""

    def __init__(self, lose: set[int], duplicate: set[int]) -> None:
        self.received: list[str] = []
        self.calls = 0
        self._lose, self._duplicate = lose, duplicate

    async def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        index = self.calls
        self.calls += 1
        if index not in self._lose:
            self.received.append(str(json["event_id"]))
            if index in self._duplicate:
                self.received.append(str(json["event_id"]))
        return httpx.Response(200, request=httpx.Request("POST", url))

    async def get(self, url: str, timeout: float = 5.0) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url))


async def test_siem_loss_and_duplication_are_detected_against_the_durable_log(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    siem = _FlakySiem(lose={1, 4}, duplicate={2})
    sink = SiemForwardAuditSink(
        JsonlDurableSecurityAuditSink(path, POLICY),
        siem,  # type: ignore[arg-type]
        "https://siem.example.invalid/ingest",
    )
    for i in range(6):
        await sink.append(_event(i))
    await sink._queue.join()
    await sink.close()

    # The local durable record is authoritative and intact even though the SIEM is not.
    assert verify_audit_log(path).ok
    durable = durable_event_ids(path)
    assert len(durable) == 6

    report = reconcile_event_ids(durable, siem.received)
    assert {durable[1], durable[4]} == report.missing
    assert report.duplicated == {durable[2]}
    assert not report.unexpected
    assert not report.ok  # an operator would backfill exactly `missing` from the durable log
