"""``python -m art_sim.bas`` — run the intrusion-simulation campaign against the local lab."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from art_sim.bas.lab import UnsafeTargetError
from art_sim.bas.runner import render_markdown, run_campaign, write_reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Breach-and-attack simulation against the synthetic lab"
    )
    parser.add_argument(
        "--out", type=Path, default=Path("out/bas"), help="directory for report + AegisTrace"
    )
    parser.add_argument(
        "--postgres-dsn",
        default=os.getenv("ART_BAS_POSTGRES_DSN"),
        help="loopback PostgreSQL DSN (default: SQLite in the output directory)",
    )
    parser.add_argument("--only", action="append", help="run only this case id (repeatable)")
    parser.add_argument("--strict", action="store_true", help="also fail on defence-in-depth gaps")
    args = parser.parse_args(argv)
    try:
        report = asyncio.run(
            run_campaign(
                args.out, postgres_dsn=args.postgres_dsn, only=set(args.only) if args.only else None
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
