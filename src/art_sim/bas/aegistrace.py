"""AegisTrace: forensic recorder for every intrusion attempt.

Each attempt becomes one *incident* appended to a hash-chained JSONL file that reuses the
platform's audit-chain envelope, so ``scripts/verify_audit_log.py`` proves — from the file
alone — that no attempt was dropped, duplicated, reordered or edited.

Design rules:

* an attempt is recorded **before** it runs (``attempt.started``) and again with its outcome
  (``attempt.finished``); a crash mid-attack therefore leaves evidence of what was tried;
* attacker payloads are never stored verbatim: a SHA-256 plus a short, redacted, escaped
  preview, so the forensic file cannot itself become an injection vector or a secret store;
* the record carries the correlation id the platform returned, tying an attempt to the
  platform's own audit events.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from art_sim.bas.models import AttackCase, Category, Observation, Verdict
from art_sim.security.audit_chain import GENESIS_HASH, build_envelope
from art_sim.security.redaction import redact_security_text

PREVIEW_CHARS = 80


class IncidentPhase(StrEnum):
    """Lifecycle marker of an incident record."""

    STARTED = "attempt.started"
    FINISHED = "attempt.finished"


class Incident(BaseModel):
    """Schema of one forensic record; extra fields are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    campaign_id: UUID
    phase: IncidentPhase
    case_id: str
    category: Category
    technique: str
    title: str
    attacker_tenant: str | None = None
    victim_tenant: str | None = None
    payload_sha256: str | None = None
    payload_preview: str | None = None
    verdict: Verdict | None = None
    status_code: int | None = None
    detail: str | None = None
    evidence_sha256: str | None = None
    detected_by_platform: bool | None = None
    platform_request_id: str | None = None


def payload_preview(payload: str) -> str:
    """Bounded, redacted, escaped rendition of attacker input (inert text)."""
    escaped = payload.encode("unicode_escape").decode("ascii")
    return (redact_security_text(escaped) or "")[:PREVIEW_CHARS]


class AegisTrace:
    """Append-only, chained incident log for one or more campaigns."""

    def __init__(self, path: Path, campaign_id: UUID | None = None) -> None:
        self._path = path
        self.campaign_id = campaign_id or uuid4()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        self._seq, self._head = self._resume()

    def _resume(self) -> tuple[int, str]:
        seq, head = 1, GENESIS_HASH
        for raw in self._path.read_text(encoding="utf-8").splitlines():
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(document, dict) and isinstance(document.get("seq"), int):
                seq, head = int(document["seq"]) + 1, str(document["hash"])
        return seq, head

    def _append(self, incident: Incident) -> None:
        envelope = build_envelope(self._seq, self._head, incident.model_dump(mode="json"))
        line = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
        self._seq += 1
        self._head = str(envelope["hash"])

    def started(self, case: AttackCase, *, attacker: str | None, victim: str | None) -> None:
        """Record the attempt before it is executed."""
        self._append(
            Incident(
                campaign_id=self.campaign_id,
                phase=IncidentPhase.STARTED,
                case_id=case.case_id,
                category=case.category,
                technique=case.technique,
                title=case.title,
                attacker_tenant=attacker,
                victim_tenant=victim,
                payload_sha256=sha256(case.payload.encode()).hexdigest() if case.payload else None,
                payload_preview=payload_preview(case.payload) if case.payload else None,
            )
        )

    def finished(
        self,
        case: AttackCase,
        observation: Observation,
        *,
        detected: bool,
        request_id: str | None,
    ) -> None:
        """Record the outcome of an attempt."""
        self._append(
            Incident(
                campaign_id=self.campaign_id,
                phase=IncidentPhase.FINISHED,
                case_id=case.case_id,
                category=case.category,
                technique=case.technique,
                title=case.title,
                verdict=observation.verdict,
                status_code=observation.status_code,
                detail=(redact_security_text(observation.detail) or "")[:240],
                evidence_sha256=sha256(observation.evidence.encode()).hexdigest()
                if observation.evidence
                else None,
                detected_by_platform=detected,
                platform_request_id=request_id,
            )
        )

    @property
    def path(self) -> Path:
        """Location of the forensic file."""
        return self._path

    @property
    def head(self) -> tuple[int, str]:
        """(last sequence, head hash) — anchor this outside the writer's trust boundary."""
        return self._seq - 1, self._head
