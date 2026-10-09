"""Summarize test results and assemble the reproducibility evidence bundle.

Two modes, both stdlib-only so they run before (and independently of) the project install:

    python scripts/evidence_summary.py junit evidence/junit.xml [--fail-on-skip REGEX]
        Print a Markdown table of the JUnit totals and every skip *with its reason*, and exit
        non-zero if there are failures/errors or a skip reason matches REGEX. Used by CI for the
        job summary, and by ``reproduce.sh --require-services`` so that "green because the
        database was missing" can never pass as a real run.

    python scripts/evidence_summary.py final --dir evidence
        Read ``steps.tsv`` (one ``name<TAB>status<TAB>detail`` line per step) plus
        ``junit.xml``, write ``SUMMARY.md`` and ``summary.json``, then ``SHA256SUMS`` over every
        file in the bundle. Exit non-zero if any step FAILED.

Step status vocabulary: PASS, FAIL, SKIP (deliberately not run, reason given) and DEGRADED
(ran, but with reduced coverage, reason given — e.g. a service was unavailable).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path


def _parse_junit(path: Path) -> dict[str, object]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    totals = Counter()
    failures: list[str] = []
    skips: Counter[str] = Counter()
    duration = 0.0
    for suite in suites:
        duration += float(suite.get("time", 0))
        for case in suite.iter("testcase"):
            totals["tests"] += 1
            name = f"{case.get('classname')}::{case.get('name')}"
            if case.find("failure") is not None or case.find("error") is not None:
                totals["failed"] += 1
                failures.append(name)
            elif (skipped := case.find("skipped")) is not None:
                totals["skipped"] += 1
                reason = (skipped.get("message") or "").strip() or "no reason recorded"
                skips[re.sub(r"^.*?:\d+: ", "", reason)] += 1
            else:
                totals["passed"] += 1
    return {
        "tests": totals["tests"],
        "passed": totals["passed"],
        "failed": totals["failed"],
        "skipped": totals["skipped"],
        "duration_seconds": round(duration, 1),
        "failures": failures,
        "skip_reasons": dict(skips),
    }


def _junit_markdown(result: dict[str, object]) -> str:
    lines = [
        "| Tests | Passed | Failed | Skipped | Duration |",
        "|---:|---:|---:|---:|---:|",
        f"| {result['tests']} | {result['passed']} | {result['failed']} | {result['skipped']} | "
        f"{result['duration_seconds']} s |",
    ]
    failures = result["failures"]
    if failures:
        lines += ["", "**Failures**", *(f"- `{name}`" for name in failures)]  # type: ignore[attr-defined]
    skips = result["skip_reasons"]
    if skips:
        lines += ["", "**Skipped, with reason** (a skip is not a pass):"]
        lines += [f"- {count} × {reason}" for reason, count in skips.items()]  # type: ignore[attr-defined]
    return "\n".join(lines)


def cmd_junit(args: argparse.Namespace) -> int:
    result = _parse_junit(args.file)
    print(_junit_markdown(result))
    bad = result["failed"] != 0
    if args.fail_on_skip:
        pattern = re.compile(args.fail_on_skip)
        offending = [r for r in result["skip_reasons"] if pattern.search(r)]  # type: ignore[attr-defined]
        if offending:
            print(f"\nFAIL: skips matching /{args.fail_on_skip}/: {offending}", file=sys.stderr)
            bad = True
    return 1 if bad else 0


def _git(*args: str) -> str:
    try:
        return subprocess.run(  # noqa: S603
            ["git", *args], capture_output=True, text=True, check=True  # noqa: S607
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def cmd_final(args: argparse.Namespace) -> int:
    evidence = args.dir
    steps = []
    steps_file = evidence / "steps.tsv"
    if steps_file.exists():
        for line in steps_file.read_text(encoding="utf-8").splitlines():
            name, _, rest = line.partition("\t")
            status, _, detail = rest.partition("\t")
            steps.append({"step": name, "status": status, "detail": detail})
    junit_path = evidence / "junit.xml"
    junit = _parse_junit(junit_path) if junit_path.exists() else None
    failed = [s for s in steps if s["status"] == "FAIL"]
    degraded = [s for s in steps if s["status"] == "DEGRADED"]
    verdict = "FAILED" if failed else ("PASSED WITH REDUCED COVERAGE" if degraded else "PASSED")
    summary = {
        "verdict": verdict,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")) if _git("rev-parse", "HEAD") != "unavailable" else None,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "steps": steps,
        "tests": junit,
    }
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    markdown = [
        "# Reproduction evidence",
        "",
        f"**Verdict: {verdict}**",
        "",
        f"- Commit: `{summary['git_commit']}`"
        + (" (working tree has uncommitted changes)" if summary["git_dirty"] else ""),
        f"- Python {summary['python']} on {summary['platform']}",
        f"- Generated: {summary['generated_at']}",
        "",
        "## Steps",
        "",
        "| Step | Result | Detail |",
        "|---|---|---|",
        *(f"| {s['step']} | {s['status']} | {s['detail']} |" for s in steps),
    ]
    if junit:
        markdown += ["", "## Test suite", "", _junit_markdown(junit)]
    markdown += [
        "",
        "## How to check this bundle",
        "",
        "- `sha256sum -c SHA256SUMS` — every file below is unmodified.",
        "- `junit.xml` — raw per-test results (any JUnit viewer).",
        "- `demo/findings.sha256` must equal `src/art_sim/demo/expected_findings.sha256`.",
        "- `python scripts/verify_audit_log.py demo/audit/security.jsonl` — audit chain intact.",
        "",
    ]
    (evidence / "SUMMARY.md").write_text("\n".join(markdown), encoding="utf-8")

    sums = []
    for path in sorted(p for p in evidence.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        # State databases and raw logs of the demo are evidence too, but the checkpoint database
        # embeds machine-specific paths, so it is hashed like everything else yet clearly listed.
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append(f"{digest}  {path.relative_to(evidence).as_posix()}")
    (evidence / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")

    print("\n".join(markdown[:12]))
    print(f"\nVERDICT: {verdict}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    sub = parser.add_subparsers(dest="mode", required=True)
    junit = sub.add_parser("junit", help="summarize a JUnit XML file")
    junit.add_argument("file", type=Path)
    junit.add_argument("--fail-on-skip", metavar="REGEX", help="fail if a skip reason matches")
    junit.set_defaults(func=cmd_junit)
    final = sub.add_parser("final", help="assemble the evidence bundle")
    final.add_argument("--dir", type=Path, required=True)
    final.set_defaults(func=cmd_final)
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
