"""Run a campaign: execute every attack, record it in AegisTrace, and produce the report."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from art_sim.bas.aegistrace import AegisTrace
from art_sim.bas.cases.datastore import datastore_cases
from art_sim.bas.cases.injection import injection_cases
from art_sim.bas.cases.prompt import prompt_cases
from art_sim.bas.cases.tenant import tenant_cases
from art_sim.bas.lab import AppFactory, Lab, default_app, open_lab
from art_sim.bas.models import AttackCase, Observation, Verdict
from art_sim.security.audit_chain import verify_audit_log


def catalogue() -> list[AttackCase]:
    """The full, ordered attack catalogue."""
    return [*tenant_cases(), *injection_cases(), *prompt_cases(), *datastore_cases()]


@dataclass(frozen=True)
class CaseResult:
    """Outcome of one attack after detection has been taken into account."""

    case_id: str
    category: str
    technique: str
    title: str
    verdict: Verdict
    status_code: int | None
    detail: str
    detected_by_platform: bool
    detection_required: bool


@dataclass(frozen=True)
class CampaignReport:
    """Everything a reviewer needs to judge a campaign without trusting the runner."""

    campaign_id: str
    backend: str
    catalogue_sha256: str
    results: tuple[CaseResult, ...]
    chain_ok: bool
    chain_events: int
    chain_head: str

    @property
    def counts(self) -> dict[str, int]:
        """Verdict histogram."""
        counter = Counter(result.verdict.value for result in self.results)
        return {verdict.value: counter.get(verdict.value, 0) for verdict in Verdict}

    def exit_code(self, *, strict: bool = False) -> int:
        """Non-zero when any control failed (or, with ``strict``, any gap/error remains)."""
        bad = {Verdict.BREACHED, Verdict.ERROR} | ({Verdict.GAP} if strict else set())
        return 1 if any(r.verdict in bad for r in self.results) or not self.chain_ok else 0


async def _execute(case: AttackCase, lab: Lab, trace: AegisTrace) -> CaseResult:
    trace.started(case, attacker=case.attacker_tenant, victim=case.victim_tenant)
    mark = lab.audit_mark()
    lab.last_request_id = None
    try:
        observation = await case.run(lab)
    except Exception as error:  # noqa: BLE001 - a crashing case must never read as a pass
        observation = Observation(
            Verdict.ERROR, f"attack case crashed: {type(error).__name__}: {error}"
        )
    detected = lab.denials_since(mark) > 0
    if observation.verdict is Verdict.BLOCKED and case.expect_detection and not detected:
        observation = Observation(
            Verdict.GAP,
            f"{observation.detail} — but the platform logged no denial for this probe",
            observation.status_code,
            observation.evidence,
        )
    trace.finished(case, observation, detected=detected, request_id=lab.last_request_id)
    return CaseResult(
        case.case_id,
        case.category.value,
        case.technique,
        case.title,
        observation.verdict,
        observation.status_code,
        observation.detail,
        detected,
        case.expect_detection,
    )


async def run_campaign(
    workdir: Path,
    *,
    postgres_dsn: str | None = None,
    app_factory: AppFactory = default_app,
    only: set[str] | None = None,
    campaign_id: UUID | None = None,
) -> CampaignReport:
    """Execute the catalogue against a fresh lab and return a verified report."""
    cases = [case for case in catalogue() if only is None or case.case_id in only]
    trace = AegisTrace(workdir / "aegistrace.jsonl", campaign_id or uuid4())
    results: list[CaseResult] = []
    async with open_lab(workdir, postgres_dsn=postgres_dsn, app_factory=app_factory) as lab:
        for case in cases:
            results.append(await _execute(case, lab, trace))
        backend = lab.backend
    verification = verify_audit_log(trace.path)
    seq, head = trace.head
    digest = sha256(
        "\n".join(f"{c.case_id}|{c.technique}|{c.title}" for c in cases).encode()
    ).hexdigest()
    return CampaignReport(
        str(trace.campaign_id), backend, digest, tuple(results), verification.ok, seq, head
    )


def render_markdown(report: CampaignReport) -> str:
    """Human-readable report; findings first."""
    counts = report.counts
    lines = [
        "# BAS campaign report",
        "",
        f"- Campaign: `{report.campaign_id}`",
        f"- Backend: **{report.backend}**",
        f"- Catalogue digest: `{report.catalogue_sha256}`",
        (
            f"- AegisTrace: {report.chain_events} records, "
            f"chain {'INTACT' if report.chain_ok else 'BROKEN'}, head `{report.chain_head[:16]}...`"
        ),
        "- Verdicts: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
        "",
    ]
    for verdict, heading in (
        (Verdict.BREACHED, "Breaches"),
        (Verdict.ERROR, "Errors"),
        (Verdict.GAP, "Gaps"),
    ):
        items = [r for r in report.results if r.verdict is verdict]
        if items:
            lines += (
                [f"## {heading}", ""]
                + [f"- **{r.case_id}** ({r.technique}) — {r.detail}" for r in items]
                + [""]
            )
    lines += [
        "## All attempts",
        "",
        "| Case | Category | Verdict | HTTP | Logged by platform |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| {r.case_id} | {r.category} | {r.verdict.value} | {r.status_code or '-'} | "
        f"{'yes' if r.detected_by_platform else ('n/a' if not r.detection_required else 'NO')} |"
        for r in report.results
    ]
    return "\n".join(lines) + "\n"


def write_reports(report: CampaignReport, out: Path) -> None:
    """Persist ``report.json`` and ``report.md`` next to the AegisTrace file."""
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        **asdict(report),
        "counts": report.counts,
        "results": [{**asdict(r), "verdict": r.verdict.value} for r in report.results],
    }
    (out / "report.json").write_text(
        json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8"
    )
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
