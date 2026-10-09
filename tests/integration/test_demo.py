"""The one-command demo is deterministic, honest, safe to run, and self-checking."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from art_sim.demo import __main__ as demo_cli
from art_sim.demo import report
from art_sim.demo.lab import lab_scenario
from art_sim.demo.runner import MARKER, prepare_output, run_lab

EXPECTED_CONTROLS = {
    "Create simulation (operator)",
    "Anonymous approval",
    "Viewer approval",
    "Foreign-organization admin approval",
    "Approval without a real review reason",
    "Result read before approval",
    "Cross-organization read",
    "Operator approval",
    "Replayed approval",
    "Read audit trail (operator)",
    "Read audit trail (admin)",
    "Approval after the window closed",
    "Cancel the expired run",
}


@pytest.fixture(scope="module")
async def first(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    out = tmp_path_factory.mktemp("demo-a") / "out"
    prepare_output(out)
    evidence = await run_lab(out)
    digest, _ = report.write_artifacts(evidence, out)
    return out, digest


async def test_every_control_exercised_held_and_none_was_skipped(
    first: tuple[Path, str],
) -> None:
    findings_path = first[0] / "findings.json"
    import json

    controls = json.loads(findings_path.read_text())["controls"]
    assert EXPECTED_CONTROLS <= {c["control"] for c in controls}
    failed = [c for c in controls if not c["held"]]
    assert not failed, failed
    # Negative controls really are refusals; the only successes are the authorized actions.
    statuses = {c["control"]: c["observed_status"] for c in controls}
    assert statuses["Anonymous approval"] == 401
    assert statuses["Viewer approval"] == 403
    assert statuses["Foreign-organization admin approval"] == 404
    assert statuses["Result read before approval"] == 409
    assert statuses["Approval after the window closed"] == 410


async def test_findings_digest_reproduces_the_committed_reference(first: tuple[Path, str]) -> None:
    """This is the check an outside reviewer performs: same digest as the one in the repo."""
    reference = report.expected_digest()
    assert reference is not None, "run `python -m art_sim.demo --update-expected` and commit it"
    assert first[1] == reference
    assert (first[0] / "findings.sha256").read_text().split()[0] == reference


async def test_two_executions_produce_byte_identical_reproducible_files(
    first: tuple[Path, str], tmp_path: Path
) -> None:
    second = tmp_path / "out"
    prepare_output(second)
    digest, _ = report.write_artifacts(await run_lab(second), second)
    assert digest == first[1]
    for name in ("findings.json", "report.md", "before.svg", "after.svg", "REPRODUCIBLE.sha256"):
        assert (second / name).read_bytes() == (first[0] / name).read_bytes(), name
    # ...while per-execution evidence legitimately differs.
    assert (second / "audit" / "security.jsonl").read_bytes() != (first[0] / "audit" / "security.jsonl").read_bytes()


async def test_findings_state_the_scenario_numbers_and_stay_synthetic(first: tuple[Path, str]) -> None:
    import json

    findings = json.loads((first[0] / "findings.json").read_text())
    assert findings["risk"]["score"] == 58.67
    assert findings["risk"]["reconciles"] is True
    assert findings["verification"]["risk_after"] == 0.0
    assert findings["blast_radius"]["before"]["percent"] == 90.0
    assert findings["blast_radius"]["after"]["percent"] == 50.0
    assert findings["blast_radius"]["after"]["crown_jewel_exposure_percent"] == 0.0
    assert findings["remediation"]["simulated_only"] is True
    assert findings["automated_preapproval"]["requires_human_approval"] is True
    assert "no real system" in findings["classification"]
    scenario = lab_scenario()
    assert all(a.environment.value == "shadow" and a.provider == "synthetic" for a in scenario.graph.assets)


async def test_audit_chain_is_intact_and_tampering_is_detected(first: tuple[Path, str]) -> None:
    text = (first[0] / "audit" / "verification.txt").read_text()
    assert "security log: ok=True" in text
    assert "ok=False" in text and "gap" in text  # the deleted-event copy was caught


async def test_html_report_is_self_contained_and_escapes_content(first: tuple[Path, str]) -> None:
    html = (first[0] / "report.html").read_text()
    assert "<script" not in html.lower()
    # No network resources: the only absolute URL allowed is the SVG XML namespace.
    urls = set(re.findall(r"https?://[^\s\"'<>)]+", html))
    assert urls <= {"http://www.w3.org/2000/svg"}, urls
    for expected in ("Why the risk is 58.67", "Human approval", "16/16 controls held", "Known limitation"):
        assert expected in html
    prose = re.sub(r"<pre>.*?</pre>", "", html, flags=re.DOTALL)
    assert "`" not in prose  # markdown backticks were rendered as <code>, not left literal


async def test_svg_figures_are_valid_xml_and_show_the_control(first: tuple[Path, str]) -> None:
    before = ET.fromstring((first[0] / "before.svg").read_text())
    after = ET.fromstring((first[0] / "after.svg").read_text())
    ns = "{http://www.w3.org/2000/svg}"
    assert before.tag == after.tag == f"{ns}svg"
    before_text = (first[0] / "before.svg").read_text()
    after_text = (first[0] / "after.svg").read_text()
    assert 'class="edge path"' in before_text and 'class="edge cut"' not in before_text
    assert 'class="edge cut"' in after_text and "blocked by approved control" in after_text
    # Same layout in both views: identical node coordinates.
    def positions(root: ET.Element) -> list[tuple[str | None, str | None]]:
        return sorted(
            (r.get("x"), r.get("y")) for r in root.iter(f"{ns}rect") if "node" in (r.get("class") or "")
        )

    assert positions(before) == positions(after)
    assert "billing-db ★" in before_text and "critical · unreachable" in after_text


async def test_markdown_report_has_no_volatile_content(first: tuple[Path, str]) -> None:
    markdown = (first[0] / "report.md").read_text()
    assert not re.search(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", markdown)
    assert not re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", markdown)
    assert first[1] in markdown
    assert "not** a 1:1 implementation" in markdown  # the generator limitation is disclosed


# ----------------------------------------------------------------------- output safety


def test_demo_refuses_to_overwrite_a_directory_it_did_not_create(tmp_path: Path) -> None:
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "notes.txt").write_text("keep me")
    with pytest.raises(FileExistsError):
        prepare_output(precious)
    assert (precious / "notes.txt").read_text() == "keep me"


def test_demo_reuses_its_own_directory_and_leaves_an_empty_one_alone(tmp_path: Path) -> None:
    mine = tmp_path / "mine"
    prepare_output(mine)
    (mine / "stale.txt").write_text("old run")
    prepare_output(mine)  # marker present -> wiped and recreated
    assert not (mine / "stale.txt").exists() and (mine / MARKER).exists()
    empty = tmp_path / "empty"
    empty.mkdir()
    prepare_output(empty)
    assert (empty / MARKER).exists()


# --------------------------------------------------------------------------------- CLI


def test_cli_reports_reproduced_and_succeeds(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = demo_cli.main(["--out", str(tmp_path / "cli"), "--quiet"])
    output = capsys.readouterr().out
    assert code == 0
    assert "REPRODUCED" in output and "RESULT: OK" in output
    assert "Controls held     : 16/16" in output


def test_cli_fails_when_the_digest_does_not_match(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(demo_cli, "expected_digest", lambda: "0" * 64)
    code = demo_cli.main(["--out", str(tmp_path / "cli"), "--quiet"])
    output = capsys.readouterr().out
    assert code == 1
    assert "MISMATCH" in output and "RESULT: FAILED" in output


def test_cli_refuses_foreign_directory_with_exit_code_2(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("not ours")
    assert demo_cli.main(["--out", str(tmp_path), "--quiet"]) == 2
