"""Tamper-evident sequencing for the durable security-audit log, and its verifier.

Every line the durable sink writes is an *envelope*::

    {"seq": 7, "prev": "<hash of seq 6>", "hash": "<sha256>", "event": {...}}

``hash`` covers ``seq``, ``prev`` and the canonical JSON of ``event``, so any consumer — an
auditor, a CI job, an on-call engineer — can re-derive the chain from the file alone and
detect, without trusting the writer:

* **lost events** — a gap in ``seq`` (or a ``prev`` that does not match the preceding hash);
* **duplicated events** — a repeated ``event_id`` or ``seq``;
* **tampering** — an edited event or hash, or reordered lines;
* **torn writes** — a malformed trailing fragment left by a crash.

What a file *cannot* reveal on its own is the loss of its newest lines (truncation): the
shorter chain is still internally consistent. ``verify_audit_log`` therefore accepts the
externally-held head (``expected_last_seq`` / ``expected_head_hash``) — e.g. what a SIEM or a
previous checkpoint recorded — and reports a truncation when the file ends earlier.
``reconcile_event_ids`` does the equivalent for a downstream stream such as a SIEM index.

This is evidence of integrity, not of authenticity: an attacker able to rewrite the whole
file can rebuild a consistent chain. Anchor the head outside the writer's trust boundary
(SIEM, object-lock bucket, signed checkpoint) for that guarantee.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

GENESIS_HASH = "0" * 64


def canonical_event_json(event: Mapping[str, object]) -> str:
    """Return the one canonical text the chain hashes (sorted keys, no whitespace)."""
    return json.dumps(event, separators=(",", ":"), sort_keys=True)


def chain_hash(seq: int, prev: str, event: Mapping[str, object]) -> str:
    """Hash one link: sequence number, predecessor hash, and canonical event body."""
    material = f"{seq}|{prev}|{canonical_event_json(event)}"
    return sha256(material.encode("utf-8")).hexdigest()


def build_envelope(seq: int, prev: str, event: Mapping[str, object]) -> dict[str, object]:
    """Wrap an already-serialized event as the next link of the chain."""
    return {"seq": seq, "prev": prev, "hash": chain_hash(seq, prev, event), "event": dict(event)}


@dataclass(frozen=True)
class ChainIssue:
    """One verifiable defect, located by 1-based file line number."""

    kind: str
    line: int
    detail: str


@dataclass(frozen=True)
class AuditVerificationReport:
    """Outcome of verifying a durable audit log; ``ok`` is the single pass/fail verdict."""

    total_lines: int
    chained_events: int
    legacy_events: int
    first_seq: int | None
    last_seq: int | None
    head_hash: str | None
    issues: tuple[ChainIssue, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """True only when no gap, duplicate, tamper, malformed line or truncation was found."""
        return not self.issues

    def kinds(self) -> frozenset[str]:
        """Distinct defect categories, convenient for assertions and alerting."""
        return frozenset(issue.kind for issue in self.issues)


def verify_audit_log(
    path: Path,
    *,
    expected_last_seq: int | None = None,
    expected_head_hash: str | None = None,
) -> AuditVerificationReport:
    """Re-derive the chain of ``path`` and report every integrity defect found."""
    lines = path.read_text(encoding="utf-8").splitlines()
    issues: list[ChainIssue] = []
    seen_event_ids: dict[str, int] = {}
    seen_seqs: dict[int, int] = {}
    prev_hash = GENESIS_HASH
    prev_seq: int | None = None
    first_seq: int | None = None
    chained = legacy = non_blank = 0

    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        non_blank += 1
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            issues.append(ChainIssue("malformed", number, "line is not valid JSON"))
            continue
        if not isinstance(document, dict):
            issues.append(ChainIssue("malformed", number, "line is not a JSON object"))
            continue
        event = document.get("event")
        if event is None:
            # Pre-chain format: the line *is* the event. Counted, never silently trusted.
            legacy += 1
            _track_event_id(document, number, seen_event_ids, issues)
            continue
        seq, prev, claimed = document.get("seq"), document.get("prev"), document.get("hash")
        if (
            not isinstance(seq, int)
            or isinstance(seq, bool)
            or not isinstance(prev, str)
            or not isinstance(claimed, str)
            or not isinstance(event, dict)
        ):
            issues.append(ChainIssue("malformed", number, "envelope fields are invalid"))
            continue
        chained += 1
        first_seq = seq if first_seq is None else first_seq
        if seq in seen_seqs:
            issues.append(
                ChainIssue("duplicate_seq", number, f"seq {seq} already seen at line {seen_seqs[seq]}")
            )
        elif prev_seq is not None and seq > prev_seq + 1:
            issues.append(ChainIssue("gap", number, f"expected seq {prev_seq + 1}, found {seq}"))
        elif prev_seq is not None and seq < prev_seq:
            issues.append(ChainIssue("out_of_order", number, f"seq {seq} follows seq {prev_seq}"))
        seen_seqs.setdefault(seq, number)
        if prev != prev_hash:
            issues.append(ChainIssue("chain_break", number, "prev does not match the prior hash"))
        if claimed != chain_hash(seq, prev, event):
            issues.append(ChainIssue("hash_mismatch", number, "event or hash was altered"))
        _track_event_id(event, number, seen_event_ids, issues)
        # Continue from what the line *claims*, so one defect does not cascade into
        # a "chain_break" on every following (otherwise intact) line.
        prev_hash = claimed
        prev_seq = seq if prev_seq is None else max(prev_seq, seq)

    if expected_last_seq is not None and (prev_seq is None or prev_seq < expected_last_seq):
        issues.append(
            ChainIssue(
                "truncated",
                len(lines),
                f"log ends at seq {prev_seq}, but seq {expected_last_seq} was previously recorded",
            )
        )
    elif (
        expected_head_hash is not None
        and expected_last_seq is not None
        and prev_seq == expected_last_seq
        and prev_hash != expected_head_hash
    ):
        issues.append(ChainIssue("head_mismatch", len(lines), "head hash differs from the anchor"))
    return AuditVerificationReport(
        total_lines=non_blank,
        chained_events=chained,
        legacy_events=legacy,
        first_seq=first_seq,
        last_seq=prev_seq,
        head_hash=prev_hash if chained else None,
        issues=tuple(issues),
    )


def _track_event_id(
    event: Mapping[str, object],
    number: int,
    seen: dict[str, int],
    issues: list[ChainIssue],
) -> None:
    event_id = event.get("event_id")
    if not isinstance(event_id, str):
        return
    if event_id in seen:
        issues.append(
            ChainIssue("duplicate_event", number, f"event_id repeated from line {seen[event_id]}")
        )
    else:
        seen[event_id] = number


@dataclass(frozen=True)
class ReconciliationReport:
    """Difference between the durable log and a downstream stream (e.g. a SIEM index)."""

    missing: frozenset[str]
    duplicated: frozenset[str]
    unexpected: frozenset[str]

    @property
    def ok(self) -> bool:
        """True when the downstream holds each durable event exactly once and nothing else."""
        return not (self.missing or self.duplicated or self.unexpected)


def reconcile_event_ids(durable: Iterable[str], received: Iterable[str]) -> ReconciliationReport:
    """Compare durable event IDs with what a downstream consumer actually received."""
    expected = set(durable)
    counts = Counter(received)
    return ReconciliationReport(
        missing=frozenset(expected - counts.keys()),
        duplicated=frozenset(event_id for event_id, count in counts.items() if count > 1),
        unexpected=frozenset(counts.keys() - expected),
    )


def durable_event_ids(path: Path) -> list[str]:
    """Return every event_id in a durable log, chained or legacy, in file order."""
    ids: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(document, dict):
            continue
        event = document.get("event", document)
        event_id = event.get("event_id") if isinstance(event, dict) else None
        if isinstance(event_id, str):
            ids.append(event_id)
    return ids
