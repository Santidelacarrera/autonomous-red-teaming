"""Breach-and-attack simulation: the campaign passes on the real app, FAILS on a leaky one.

A security test that can never fail proves nothing, so the harness is mutation-tested: the
same campaign is pointed at applications with a deliberately removed control and must report
a breach and a non-zero exit code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID

import httpx
import pytest

from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationService,
)
from art_sim.bas.aegistrace import AegisTrace, payload_preview
from art_sim.bas.authorization import GrantedAuthorization
from art_sim.bas.lab import (
    SCENARIO,
    RecordingAuditSink,
    UnsafeTargetError,
    open_lab,
    require_loopback_dsn,
)
from art_sim.bas.models import Verdict
from art_sim.bas.runner import catalogue, render_markdown, run_campaign, write_reports
from art_sim.platform.health import HealthService
from art_sim.platform.models import SimulationRun
from art_sim.platform.ports import OperationalStore
from art_sim.security.audit_chain import verify_audit_log

pytest_plugins = ["bas_plugin"]  # provides the `bas_grant` fixture

POSTGRES_DSN = os.getenv("ART_BAS_TEST_POSTGRES_DSN")


async def _healthy() -> None:
    """Deterministic readiness dependency."""


def _compose(service: SimulationService, store: OperationalStore, audit: RecordingAuditSink):  # type: ignore[no-untyped-def]
    return create_app(
        service,
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_audit=audit,
        cancellation_service=CancellationService(store),
    )


def _verdicts(report) -> dict[str, Verdict]:  # type: ignore[no-untyped-def]
    return {r.case_id: r.verdict for r in report.results}


# ----------------------------------------------------------------------- the real application


async def test_campaign_finds_no_breach_on_the_real_application(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant)
    verdicts = _verdicts(report)
    assert report.exit_code() == 0
    assert not [c for c, v in verdicts.items() if v in (Verdict.BREACHED, Verdict.ERROR)]
    # The only open finding is the documented one: no database-level tenant boundary.
    assert {c for c, v in verdicts.items() if v is Verdict.GAP} == {"DS-RLS-POSTURE"}
    assert report.exit_code(strict=True) == 1
    assert set(verdicts) == {case.case_id for case in catalogue()}
    assert report.chain_ok and report.chain_events == 1 + 2 * len(
        verdicts
    )  # +1: authorization record


async def test_campaign_is_deterministic_in_what_it_attacks(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    first = await run_campaign(tmp_path / "a", authorization=bas_grant)
    second = await run_campaign(tmp_path / "b", authorization=bas_grant)
    assert first.catalogue_sha256 == second.catalogue_sha256
    assert _verdicts(first) == _verdicts(second)


@pytest.mark.skipif(
    not POSTGRES_DSN, reason="ART_BAS_TEST_POSTGRES_DSN is not set; real PostgreSQL not attacked"
)
async def test_campaign_on_real_postgresql(tmp_path: Path, bas_grant: GrantedAuthorization) -> None:
    assert POSTGRES_DSN is not None
    report = await run_campaign(tmp_path, authorization=bas_grant, postgres_dsn=POSTGRES_DSN)
    verdicts = _verdicts(report)
    assert report.backend == "postgresql"
    assert report.exit_code() == 0
    assert verdicts["DS-RLS-POSTURE"] is Verdict.GAP  # RLS is not enabled: reported, not hidden
    assert verdicts["DS-ORG-SQLI"] is Verdict.BLOCKED


# ------------------------------------------------------------------ the harness can detect a breach


class _LeakyService(SimulationService):
    """Regression under test: tenant mediation removed from the run lookup."""

    async def get_scoped(self, run_id: str | UUID, organization_id: str) -> SimulationRun:
        return await self.get(str(run_id))


def _leaky_isolation(store: OperationalStore, audit: RecordingAuditSink):  # type: ignore[no-untyped-def]
    return _compose(_LeakyService(store, ScenarioCatalog((SCENARIO,))), store, audit)


async def test_removing_tenant_mediation_is_reported_as_a_breach(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant, app_factory=_leaky_isolation)
    breached = {c for c, v in _verdicts(report).items() if v is Verdict.BREACHED}
    assert {
        "TEN-ROUTE-GET-RUN",
        "TEN-ROUTE-POST-CANCEL",
        "TEN-APPROVAL-XORG",
        "TEN-ENUM-ORACLE",
    } <= breached
    assert report.exit_code() == 1


class _UnscopedList(SimulationService):
    """Regression under test: the list endpoint forgets the organization filter."""

    async def list(self, limit, offset, status, organization_id=None):  # type: ignore[no-untyped-def]
        return await super().list(limit, offset, status, None)


async def test_removing_the_list_filter_is_reported_as_a_breach(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    def factory(store: OperationalStore, audit: RecordingAuditSink):  # type: ignore[no-untyped-def]
        return _compose(_UnscopedList(store, ScenarioCatalog((SCENARIO,))), store, audit)

    report = await run_campaign(
        tmp_path,
        authorization=bas_grant,
        app_factory=factory,
        only={"TEN-LIST-LEAK", "TEN-ROUTE-GET-RUN"},
    )
    assert _verdicts(report)["TEN-LIST-LEAK"] is Verdict.BREACHED
    assert (
        _verdicts(report)["TEN-ROUTE-GET-RUN"] is Verdict.BLOCKED
    )  # only the list control was removed


async def test_a_block_that_the_platform_did_not_log_is_a_gap(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    class _Silent(RecordingAuditSink):
        async def append(self, event) -> None:  # type: ignore[no-untyped-def]
            return None  # the platform "forgets" to audit

    def factory(store: OperationalStore, audit: RecordingAuditSink):  # type: ignore[no-untyped-def]
        return _compose(SimulationService(store, ScenarioCatalog((SCENARIO,))), store, _Silent())

    report = await run_campaign(
        tmp_path, authorization=bas_grant, app_factory=factory, only={"TEN-ROUTE-GET-RUN"}
    )
    result = report.results[0]
    assert result.verdict is Verdict.GAP and "logged no denial" in result.detail


async def test_a_crashing_case_never_reads_as_a_pass(
    tmp_path: Path, bas_grant: GrantedAuthorization, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dataclasses

    from art_sim.bas import runner

    async def boom(lab):  # type: ignore[no-untyped-def]
        raise RuntimeError("harness bug")

    original = runner.catalogue()
    # Only the body changes; id, technique and title (hence the authorised digest) do not.
    monkeypatch.setattr(
        runner, "catalogue", lambda: [dataclasses.replace(original[0], run=boom), *original[1:]]
    )
    report = await run_campaign(tmp_path, authorization=bas_grant, only={original[0].case_id})
    assert report.results[0].verdict is Verdict.ERROR and report.exit_code() == 1


# --------------------------------------------------------------------------------- AegisTrace


async def test_every_attempt_is_recorded_before_and_after_it_runs(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant)
    lines = [json.loads(x) for x in (tmp_path / "aegistrace.jsonl").read_text().splitlines()]
    assert lines[0]["event"]["phase"] == "campaign.authorized"  # the permission is on record first
    assert lines[0]["event"]["authorized_by"] == "Test Owner"
    phases = [(l["event"]["case_id"], l["event"]["phase"]) for l in lines[1:]]
    for case in catalogue():
        assert phases.index((case.case_id, "attempt.started")) + 1 == phases.index(
            (case.case_id, "attempt.finished")
        )
    assert report.chain_ok


async def test_trace_is_tamper_evident_and_never_stores_raw_payloads(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    await run_campaign(tmp_path, authorization=bas_grant)
    path = tmp_path / "aegistrace.jsonl"
    text = path.read_text()
    assert "DROP TABLE" in text  # the bounded, escaped preview is kept for the analyst …
    from art_sim.bas.corpus import PROMPT_INJECTION

    joined = " | ".join(PROMPT_INJECTION)[:512]
    assert (
        joined not in text and joined.encode("unicode_escape").decode() not in text
    )  # … never whole payloads
    assert all(
        len(json.loads(x)["event"].get("payload_preview") or "") <= 80 for x in text.splitlines()
    )
    assert "payload_sha256" in text  # integrity of what was sent is still provable
    assert verify_audit_log(path).ok
    lines = text.splitlines()
    target = next(i for i, line in enumerate(lines) if '"verdict":"blocked"' in line)
    edited = lines[target].replace('"verdict":"blocked"', '"verdict":"breached"')
    assert edited != lines[target], "the forgery must actually change the record"
    lines[target] = edited
    forged = tmp_path / "forged.jsonl"
    forged.write_text("\n".join(lines) + "\n")
    assert not verify_audit_log(forged).ok
    dropped = tmp_path / "dropped.jsonl"
    dropped.write_text("\n".join(lines[:20] + lines[21:]) + "\n")
    assert "gap" in verify_audit_log(dropped).kinds()
    truncated = verify_audit_log(path, expected_last_seq=len(lines) + 5)
    assert "truncated" in truncated.kinds()


def test_payload_preview_is_inert_and_bounded() -> None:
    preview = payload_preview("line1\nline2\x00 <script> " + "A" * 500 + " Bearer abc.def.ghi")
    assert "\n" not in preview and "\x00" not in preview and len(preview) <= 80
    assert payload_preview("Authorization: Bearer abc.def.ghi") == "[REDACTED]"


async def test_trace_resumes_the_chain_across_campaigns(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    await run_campaign(tmp_path, authorization=bas_grant, only={"INJ-OVERSIZE"})
    await run_campaign(tmp_path, authorization=bas_grant, only={"INJ-OVERSIZE"})
    report = verify_audit_log(tmp_path / "aegistrace.jsonl")
    assert report.ok and report.chained_events == 6  # 2 x (authorization + started + finished)
    trace = AegisTrace(tmp_path / "aegistrace.jsonl")
    assert trace.head[0] == 6


# ------------------------------------------------------------------------------------- safety


async def test_the_lab_can_only_talk_to_itself(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    async with open_lab(tmp_path) as lab:
        assert isinstance(lab.client._transport, httpx.ASGITransport)
        with pytest.raises(httpx.ConnectError):
            async with httpx.AsyncClient() as real:
                await real.get(
                    "http://lab.invalid/health"
                )  # the name does not resolve outside the lab


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://u@db.example.com/prod",
        "postgresql://u@10.0.0.5/prod",
        "postgresql://u@203.0.113.9:5432/prod",
        "postgresql://u@/prod",
    ],
)
def test_remote_databases_are_refused(dsn: str) -> None:
    with pytest.raises(UnsafeTargetError):
        require_loopback_dsn(dsn)


@pytest.mark.parametrize(
    "dsn", ["postgresql://u@127.0.0.1/db", "postgresql://u@localhost/db", "postgresql://u@[::1]/db"]
)
def test_loopback_databases_are_allowed(dsn: str) -> None:
    require_loopback_dsn(dsn)


async def test_reports_are_written_and_readable(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant, only={"TEN-NO-CREDS"})
    write_reports(report, tmp_path)
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["counts"]["blocked"] == 1 and data["chain_ok"] is True
    assert "TEN-NO-CREDS" in render_markdown(report)
