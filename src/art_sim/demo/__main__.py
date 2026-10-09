"""``python -m art_sim.demo`` — run the whole laboratory demonstration with one command.

Offline, credential-free and simulation-only. Exit status is 0 only when every control held,
the audit hash chain verified and — if a reference digest is committed — the findings digest
reproduced it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from art_sim.demo.report import (
    DIGEST_FILE,
    HASHES_FILE,
    expected_digest,
    expected_hashes,
    write_artifacts,
)
from art_sim.demo.runner import prepare_output, run_lab


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m art_sim.demo", description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("out/demo"), help="output directory (default: out/demo)")
    parser.add_argument(
        "--update-expected",
        action="store_true",
        help="maintainers only: record this run's findings digest as the committed reference",
    )
    parser.add_argument("--quiet", action="store_true", help="print only the final verdict")
    args = parser.parse_args(argv)

    def narrate(message: str) -> None:
        if not args.quiet:
            print(message, flush=True)

    try:
        prepare_output(args.out)
    except FileExistsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    narrate("Autonomous Red Teaming — lab demonstration (synthetic data, simulation only)\n")
    evidence = asyncio.run(run_lab(args.out, narrate))
    digest, files = write_artifacts(evidence, args.out)

    if args.update_expected:
        DIGEST_FILE.write_text(f"{digest}  findings.json\n", encoding="utf-8")
        HASHES_FILE.write_text((args.out / "REPRODUCIBLE.sha256").read_text(encoding="utf-8"), encoding="utf-8")
        narrate(f"\nRecorded reference digest and file hashes in {DIGEST_FILE.parent}")

    held = sum(c.passed for c in evidence.controls)
    total = len(evidence.controls)
    reference = expected_digest()
    reference_hashes = expected_hashes()
    actual_hashes = {
        name: digest_
        for digest_, name in (
            line.split() for line in (args.out / "REPRODUCIBLE.sha256").read_text(encoding="utf-8").splitlines()
        )
    }
    if reference is None:
        reproduced = "no reference digest committed"
        digest_ok = True
    elif reference != digest:
        reproduced = f"MISMATCH (findings digest differs; expected {reference})"
        digest_ok = False
    elif reference_hashes is not None and reference_hashes != actual_hashes:
        differing = sorted(n for n in actual_hashes if actual_hashes[n] != reference_hashes.get(n))
        reproduced = f"MISMATCH (files differ from the committed hashes: {', '.join(differing)})"
        digest_ok = False
    else:
        covered = len(reference_hashes) if reference_hashes else 1
        reproduced = f"REPRODUCED (findings digest + {covered} file hashes match the committed reference)"
        digest_ok = True

    verification = evidence.result.verification
    names = {asset.asset_id: asset.name for asset in evidence.scenario.graph.assets}
    route = " -> ".join(names[asset_id] for asset_id in evidence.path.asset_ids)
    print(
        "\n"
        f"  Attack route      : {route}\n"
        f"  Risk              : {verification.risk_before:.2f} -> {verification.risk_after:.2f} (verification: {verification.status.value})\n"
        f"  Blast radius      : {verification.blast_radius_before.blast_radius_percentage:.0f}% -> "
        f"{verification.blast_radius_after.blast_radius_percentage:.0f}%\n"
        f"  Human approval    : {evidence.result.approval.decision.value if evidence.result.approval else 'none'} by "
        f"{evidence.result.approval.operator if evidence.result.approval else '-'}\n"
        f"  Controls held     : {held}/{total}\n"
        f"  Audit chain       : {'intact' if evidence.audit_report.ok else 'BROKEN'} "
        f"({evidence.audit_report.chained_events} events); tamper detected: {not evidence.tamper_report.ok}\n"
        f"  Findings digest   : {digest}\n"
        f"  Reproducibility   : {reproduced}\n"
        f"\n  Open: {files['report.html']}\n"
    )
    ok = held == total and evidence.audit_report.ok and not evidence.tamper_report.ok and digest_ok
    print("RESULT: OK" if ok else "RESULT: FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
