"""Run a campaign: execute every attack, record it in AegisTrace, and produce the report."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from art_sim.bas.aegistrace import AegisTrace
from art_sim.bas.authorization import GrantedAuthorization, backend_label
from art_sim.bas.cases.datastore import datastore_cases
from art_sim.bas.cases.injection import injection_cases
from art_sim.bas.cases.prompt import prompt_cases
from art_sim.bas.cases.tenant import tenant_cases
from art_sim.bas.lab import AppFactory, Lab, default_app, open_lab, require_loopback_dsn
from art_sim.bas.models import AttackCase, Observation, Verdict
from art_sim.bas.scenarios import SCENARIOS, ScenarioStatus, cases_of, scenario_status
from art_sim.security.audit_chain import verify_audit_log


def catalogue() -> list[AttackCase]:
    """The full, ordered attack catalogue."""
    return [*tenant_cases(), *injection_cases(), *prompt_cases(), *datastore_cases()]


def catalogue_digest() -> str:
    """Digest of the *whole* catalogue (cases and their grouping): what an authorization covers."""
    cases = catalogue()
    ids = [case.case_id for case in cases]
    lines = [f"{c.case_id}|{c.technique}|{c.title}" for c in cases]
    lines += [f"{s.scenario_id}|{','.join(cases_of(s, ids))}" for s in SCENARIOS]
    return sha256("\n".join(lines).encode()).hexdigest()


@dataclass(frozen=True)
class ScenarioResult:
    """Outcome of one scenario, derived only from its cases' verdicts."""

    scenario_id: str
    name: str
    objective: str
    success_criterion: str
    status: ScenarioStatus
    cases: tuple[str, ...]


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
    scenarios: tuple[ScenarioResult, ...] = ()
    fingerprint: str = ""
    authorized_by: str = ""
    authorization_sha256: str = ""

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


def campaign_fingerprint(results: tuple[CaseResult, ...]) -> str:
    """Reproducibility digest: what was attacked and what happened, without ids or times.

    Two campaigns of the same catalogue against the same backend must produce the same value;
    ``expected_fingerprint.sha256`` pins it for the SQLite lab so a reviewer can compare.
    """
    material = json.dumps(
        [
            [r.case_id, r.verdict.value, r.status_code, r.detail, r.detected_by_platform]
            for r in results
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(material.encode()).hexdigest()


def _scenario_results(results: tuple[CaseResult, ...]) -> tuple[ScenarioResult, ...]:
    by_case = {r.case_id: r.verdict for r in results}
    ids = [case.case_id for case in catalogue()]
    return tuple(
        ScenarioResult(
            s.scenario_id,
            s.name,
            s.objective,
            s.success_criterion,
            scenario_status([by_case[c] for c in cases_of(s, ids) if c in by_case]),
            cases_of(s, ids),
        )
        for s in SCENARIOS
    )


async def run_campaign(
    workdir: Path,
    *,
    authorization: GrantedAuthorization,
    postgres_dsn: str | None = None,
    app_factory: AppFactory = default_app,
    only: set[str] | None = None,
    campaign_id: UUID | None = None,
) -> CampaignReport:
    """Execute the catalogue against a fresh lab and return a verified report."""
    if not isinstance(authorization, GrantedAuthorization):
        raise TypeError("a campaign needs a GrantedAuthorization from verify_authorization()")
    if postgres_dsn is not None:
        require_loopback_dsn(postgres_dsn)  # before anything is created on disk
    backend_name = backend_label(postgres_dsn)
    if backend_name not in authorization.backends:
        raise PermissionError(f"backend {backend_name!r} is outside the authorization")
    if authorization.catalogue_sha256 != catalogue_digest():
        raise PermissionError("the authorization does not cover this catalogue")
    cases = [case for case in catalogue() if only is None or case.case_id in only]
    trace = AegisTrace(workdir / "aegistrace.jsonl", campaign_id or uuid4())
    trace.authorized(authorization, backend_name)
    results: list[CaseResult] = []
    async with open_lab(workdir, postgres_dsn=postgres_dsn, app_factory=app_factory) as lab:
        for case in cases:
            results.append(await _execute(case, lab, trace))
        backend = lab.backend
    verification = verify_audit_log(trace.path)
    seq, head = trace.head
    done = tuple(results)
    return CampaignReport(
        str(trace.campaign_id),
        backend,
        catalogue_digest(),
        done,
        verification.ok,
        seq,
        head,
        _scenario_results(done),
        campaign_fingerprint(done),
        authorization.authorized_by,
        authorization.file_sha256,
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
        (
            f"- Authorised by: {report.authorized_by} "
            f"(authorization sha256 `{report.authorization_sha256[:16]}...`)"
        ),
        f"- Reproducibility fingerprint: `{report.fingerprint}`",
        "- Scope: synthetic local lab only (Nexus Security & AI Lab)",
        "",
        "## Scenarios",
        "",
        "| Scenario | Status | Success criterion |",
        "|---|---|---|",
        *(
            f"| {s.scenario_id} {s.name} | {s.status.value} | {s.success_criterion} |"
            for s in report.scenarios
        ),
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
        "scenarios": [{**asdict(s), "status": s.status.value} for s in report.scenarios],
    }
    (out / "report.json").write_text(
        json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8"
    )
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
