"""``python -m art_sim.bas`` — run the intrusion-simulation campaign against the local lab.

Nothing runs without a valid written authorization (exit code 3). Listing the scenarios and
printing the catalogue digest are read-only and do not need one.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from art_sim.bas.authorization import (
    AuthorizationError,
    backend_label,
    verify_authorization,
)
from art_sim.bas.lab import UnsafeTargetError
from art_sim.bas.runner import (
    catalogue,
    catalogue_digest,
    render_markdown,
    run_campaign,
    write_reports,
)
from art_sim.bas.scenarios import render_scenarios_markdown

EXIT_NOT_AUTHORISED = 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Breach-and-attack simulation against the synthetic local lab (Nexus Security & AI Lab)"
    )
    parser.add_argument(
        "--out", type=Path, default=Path("out/bas"), help="report + AegisTrace directory"
    )
    parser.add_argument(
        "--authorization",
        type=Path,
        default=Path(os.environ["ART_BAS_AUTHORIZATION"])
        if os.getenv("ART_BAS_AUTHORIZATION")
        else None,
        help="written authorization file (default: authorizations/local-lab.json if present)",
    )
    parser.add_argument(
        "--postgres-dsn",
        default=os.getenv("ART_BAS_POSTGRES_DSN"),
        help="loopback PostgreSQL DSN (default: SQLite in the output directory)",
    )
    parser.add_argument("--only", action="append", help="run only this case id (repeatable)")
    parser.add_argument("--strict", action="store_true", help="also fail on defence-in-depth gaps")
    parser.add_argument(
        "--list-scenarios", action="store_true", help="print the scenario catalogue (read-only)"
    )
    parser.add_argument(
        "--print-catalogue-digest", action="store_true", help="print the digest to authorise"
    )
    args = parser.parse_args(argv)

    if args.print_catalogue_digest:
        print(catalogue_digest())
        return 0
    if args.list_scenarios:
        print(render_scenarios_markdown([case.case_id for case in catalogue()]), end="")
        return 0

    # The gate comes first: before the output directory exists and before any store is opened.
    try:
        grant = verify_authorization(
            args.authorization,
            catalogue_sha256=catalogue_digest(),
            backend=backend_label(args.postgres_dsn),
        )
    except AuthorizationError as error:
        print(f"refused: {error}", file=sys.stderr)
        return EXIT_NOT_AUTHORISED
    try:
        report = asyncio.run(
            run_campaign(
                args.out,
                authorization=grant,
                postgres_dsn=args.postgres_dsn,
                only=set(args.only) if args.only else None,
            )
        )
    except UnsafeTargetError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2
    write_reports(report, args.out)
    print(render_markdown(report))
    return report.exit_code(strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
