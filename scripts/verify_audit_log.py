"""Verify the integrity of a durable security-audit log (hash chain, gaps, duplicates).

Usage:

    python scripts/verify_audit_log.py var/audit/security.jsonl
    python scripts/verify_audit_log.py audit.jsonl --expected-last-seq 120 --expected-head <sha256>
    python scripts/verify_audit_log.py audit.jsonl --siem-ids siem-export.txt   # one event_id/line

Exit status is 0 only when the log is intact (and, with ``--siem-ids``, the SIEM holds every
event exactly once). Anything else prints each defect with its line number and exits 1, so it
is directly usable as a CI or cron gate. No secrets and no network access are involved.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from art_sim.security.audit_chain import durable_event_ids, reconcile_event_ids, verify_audit_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("log", type=Path, help="path to the JSONL audit log")
    parser.add_argument("--expected-last-seq", type=int, help="newest sequence number recorded elsewhere")
    parser.add_argument("--expected-head", help="head hash recorded elsewhere (needs --expected-last-seq)")
    parser.add_argument("--siem-ids", type=Path, help="file with the event_ids the SIEM received")
    args = parser.parse_args(argv)

    if not args.log.is_file():
        print(f"error: {args.log} does not exist", file=sys.stderr)
        return 2
    report = verify_audit_log(
        args.log, expected_last_seq=args.expected_last_seq, expected_head_hash=args.expected_head
    )
    print(
        f"lines={report.total_lines} chained={report.chained_events} legacy={report.legacy_events} "
        f"seq={report.first_seq}..{report.last_seq} head={report.head_hash}"
    )
    for issue in report.issues:
        print(f"  [{issue.kind}] line {issue.line}: {issue.detail}")
    ok = report.ok

    if args.siem_ids is not None:
        received = [line.strip() for line in args.siem_ids.read_text().splitlines() if line.strip()]
        reconciliation = reconcile_event_ids(durable_event_ids(args.log), received)
        print(
            f"siem: missing={len(reconciliation.missing)} "
            f"duplicated={len(reconciliation.duplicated)} unexpected={len(reconciliation.unexpected)}"
        )
        for label, ids in (
            ("missing", reconciliation.missing),
            ("duplicated", reconciliation.duplicated),
            ("unexpected", reconciliation.unexpected),
        ):
            for event_id in sorted(ids):
                print(f"  [{label}] {event_id}")
        ok = ok and reconciliation.ok

    print("RESULT: OK" if ok else "RESULT: FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
