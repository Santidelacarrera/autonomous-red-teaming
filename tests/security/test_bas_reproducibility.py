"""Reproducibility: the same catalogue against the same lab gives the same observable result.

``fingerprint`` digests what was attacked and what happened (case, verdict, status, detail,
whether the platform logged it) — never run ids, request ids or times. The SQLite value is
committed in ``src/art_sim/bas/expected_fingerprint.sha256`` so an outside reviewer can compare
their own run with ours.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

from bas_fixtures import write_authorization

from art_sim.bas.authorization import GrantedAuthorization
from art_sim.bas.runner import run_campaign
from art_sim.security.audit_chain import verify_audit_log

pytest_plugins = ["bas_plugin"]  # provides the `bas_grant` fixture

REPO = Path(__file__).resolve().parents[2]
GOLDEN = (REPO / "src" / "art_sim" / "bas" / "expected_fingerprint.sha256").read_text().strip()


async def test_the_fingerprint_matches_the_committed_reference(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant)
    assert report.backend == "sqlite"
    assert report.fingerprint == GOLDEN, (
        "the observable behaviour of the lab changed. If that is intended, review the report and "
        "update src/art_sim/bas/expected_fingerprint.sha256 with the value printed in report.md"
    )


async def test_repeated_campaigns_are_identical_in_everything_observable(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    runs = [
        await run_campaign(tmp_path / str(i), authorization=bas_grant, campaign_id=uuid4())
        for i in range(3)
    ]
    assert len({r.fingerprint for r in runs}) == 1
    assert (
        len({r.campaign_id for r in runs}) == 3
    )  # ids differ and do not leak into the fingerprint
    assert [
        [(c.case_id, c.verdict, c.status_code, c.detail) for c in r.results] for r in runs[1:]
    ] == [[(c.case_id, c.verdict, c.status_code, c.detail) for c in runs[0].results]] * 2


async def test_the_fingerprint_is_sensitive_to_a_real_change(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    from test_bas_framework import _leaky_isolation

    clean = await run_campaign(tmp_path / "clean", authorization=bas_grant)
    leaky = await run_campaign(
        tmp_path / "leaky", authorization=bas_grant, app_factory=_leaky_isolation
    )
    assert clean.fingerprint != leaky.fingerprint


async def test_every_campaign_leaves_a_verifiable_forensic_log(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant)
    verification = verify_audit_log(tmp_path / "aegistrace.jsonl")
    assert verification.ok and verification.chained_events == report.chain_events


def _cli(workdir: Path, out: Path, authorization: Path) -> dict[str, Any]:
    """A fresh interpreter, a different working directory: nothing is shared with this process."""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "art_sim.bas",
            "--out",
            str(out),
            "--authorization",
            str(authorization),
        ],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report: dict[str, Any] = json.loads((out / "report.json").read_text())
    return report


def test_independent_processes_reproduce_the_committed_fingerprint(tmp_path: Path) -> None:
    auth = write_authorization(tmp_path / "auth.json")
    first = _cli(tmp_path, tmp_path / "one", auth)
    second = _cli(tmp_path, tmp_path / "two", auth)
    assert first["fingerprint"] == second["fingerprint"] == GOLDEN
    assert first["catalogue_sha256"] == second["catalogue_sha256"]
    assert (
        first["counts"] == second["counts"] == {"blocked": 33, "breached": 0, "gap": 1, "error": 0}
    )
    assert [s["status"] for s in first["scenarios"]] == [s["status"] for s in second["scenarios"]]


def test_a_process_without_authorization_reproduces_nothing(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-I", "-m", "art_sim.bas", "--out", str(tmp_path / "out")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 3 and not (tmp_path / "out").exists()
