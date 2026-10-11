# Breach-and-attack simulation (BAS) and AegisTrace

A controlled harness that attacks the platform's own trust boundaries and records every attempt as
tamper-evident forensic evidence. It answers one question per boundary: *does the control hold,
and did the platform notice?*

```bash
make bas                       # SQLite lab           -> out/bas/{report.md,report.json,aegistrace.jsonl}
python -m art_sim.bas --out out/bas --postgres-dsn postgresql://user@127.0.0.1:5432/scratchdb
make bas STRICT=1              # also fail on defence-in-depth gaps
python scripts/verify_audit_log.py out/bas/aegistrace.jsonl
```

Exit code: `0` no breach · `1` a control failed (or, with `--strict`, a gap remains) · `2` unsafe target refused.

## What it is not

* **Not a scanner for real systems.** The only target is an in-process lab: HTTP goes through
  `httpx.ASGITransport` (no socket, no DNS), data is two fictional tenants, and the optional
  PostgreSQL must be on **loopback** — anything else is refused (`UnsafeTargetError`).
  Point `--postgres-dsn` at a *scratch database*: the campaign adds rows to it.
* **Not a source of new attack algorithms.** Payloads are inert strings used to test input handling.
* **Not covering endpoints that do not exist.** The repository has no "retrieval" or "consensus"
  endpoint; the HTTP surface is the 20 routes in `src/art_sim/api/app.py`. When such endpoints are
  added, add cases in `src/art_sim/bas/cases/` (see *Adding a case*).

## Architecture

```
            AttackCase catalogue (34)                      synthetic lab (in process)
 ┌───────────────────────────────────────────┐        ┌────────────────────────────────────┐
 │ tenant   TEN-*  (19)  cross-tenant, roles │  run   │ FastAPI app  ◄── httpx ASGITransport│
 │ injection INJ-* (10)  SQL/hdr/type/size   │ ─────► │ tenants: acme, globex (1 run each) │
 │ prompt    PI-*  (3)   planner context     │        │ store: SQLite | loopback PostgreSQL │
 │ datastore DS-*  (2)   org filter, RLS     │        │ RecordingAuditSink (platform's own) │
 └───────────────────────────────────────────┘        └────────────────────────────────────┘
        │ started / finished                                   │ denial events counted per attack
        ▼                                                      ▼
   AegisTrace (hash-chained JSONL)  ◄── runner: verdict + "did the platform log it?" ──► report.md/json
```

**Verdicts.** `blocked` the control held (and, where required, the platform logged the probe) ·
`breached` the attacker got something the control must deny · `gap` held, but a defence-in-depth
property is missing (database has no RLS; a block was not logged) · `error` the harness could not
conclude — never a pass.

**Detection is part of the test.** For cases with `expect_detection`, a block that the platform's
audit stream did not record becomes a `gap`: an invisible attack is a finding even if it failed.

### AegisTrace

Each attempt writes `attempt.started` *before* it runs and `attempt.finished` after, so a crash
mid-attack still leaves evidence. Records use the platform's audit-chain envelope
(`seq`, `prev`, `hash`), so `verify_audit_log.py` proves from the file alone that nothing was
dropped, duplicated, reordered or edited; anchor `(last seq, head hash)` outside the writer to
also detect truncation. Attacker payloads are **never stored verbatim**: SHA-256 plus an escaped,
redacted, 80-character preview, so the forensic file cannot become an injection vector.
Fields: campaign, case, technique (MITRE ATT&CK / ATLAS id), attacker and victim tenant, verdict,
HTTP status, evidence digest, whether the platform detected it, the platform's request id.

## Catalogue

| Family | Cases | Attacker | Pass means |
|---|---|---|---|
| Tenant isolation | `TEN-ROUTE-*` (11 routes) | admin of tenant B vs. tenant A's run | 404 identical to an unknown run (no existence oracle), victim state unchanged, probe logged |
| | `TEN-LIST-LEAK`, `TEN-HDR-SPOOF`, `TEN-BODY-SPOOF`, `TEN-IDEMPOTENCY`, `TEN-APPROVAL-XORG`, `TEN-ENUM-ORACLE` | tenant B | no list/filter/header/body/idempotency path crosses the boundary |
| | `TEN-VIEWER-ESC`, `TEN-NO-CREDS` | viewer / anonymous | 403 / 401 and no state change |
| Injection | `INJ-SCENARIO/STATUS/PAGING/IDEMPOTENCY/RUNID/REASON/BEARER` | SQL, path, template payloads in every input surface | no 5xx, no internal error text, victim untouched |
| | `INJ-CRLF`, `INJ-OVERSIZE`, `INJ-TYPES` | header splitting, 70 KB body, malformed JSON | not reflected, 413, service still healthy |
| Prompt injection | `PI-ALLOWLIST` | hostile asset names/tags/edge properties (16 payloads) | planner context holds only allow-listed fields (**control**) |
| | `PI-SANITIZE` | zero-width / homoglyph / NBSP obfuscation | `sanitize_text` neutralises them (defence in depth) |
| | `PI-ROUNDTRIP` | stored approval reason | returned only as `application/json` + `nosniff`, absent from the audit stream |
| Datastore | `DS-ORG-SQLI` | hostile organization filter | parameter-bound; matches nothing |
| | `DS-RLS-POSTURE` | unscoped read with the app's own DB role | **database enforces a tenant boundary (it does not — see below)** |

## Findings from the first campaign

| Finding | Status |
|---|---|
| Tenant isolation, injection and prompt-injection **controls held** (33/34 blocked on SQLite and on PostgreSQL 16) | verified |
| **No row-level security.** Tenant isolation is enforced only by application filters on `organization_id` (stored inside a JSON payload, not a column). On real PostgreSQL an unscoped `SELECT` sees both tenants and RLS is off on all 7 tables. Any code path that forgets the filter, or any direct DB access, crosses tenants. | **open `gap`** — `DS-RLS-POSTURE` |
| `sanitize_text` was bypassed by 4 of 16 obfuscated payloads (zero-width characters, dotless i) | fixed (NFKC + format-character removal + look-alike folding); regression tests added |

Closing the RLS gap is a schema change, not a test change: promote `organization_id` to a column,
`ENABLE`/`FORCE ROW LEVEL SECURITY`, a policy on `current_setting('app.organization_id')`, set per
transaction by the store, and an application role without `BYPASSRLS`. When that lands,
`DS-RLS-POSTURE` flips to `blocked` by itself — the probe measures the database, it does not
assume.

## The harness is mutation-tested

A security test that cannot fail proves nothing. `tests/security/test_bas_framework.py` points the
same campaign at applications with a control deliberately removed and requires a breach and exit
code 1: tenant mediation removed from the run lookup (11 routes + approval + oracle fail), the list
filter removed, the platform's audit made silent (→ `gap`), a crashing case (→ `error`). It also
proves AegisTrace detects edited, dropped and truncated records and never stores whole payloads.

## Adding a case

```python
# src/art_sim/bas/cases/tenant.py
async def _my_attack(lab: Lab) -> Observation:
    response = await lab.request("GET", f"/api/v1/simulations/{lab.victim_runs['acme']}/x",
                                 headers=bearer("admin", "mallory", "globex"))
    return blocked(response, "...") if response.status_code == 404 else breached(response, "...")

AttackCase("TEN-MY-ATTACK", Category.TENANT_ISOLATION, "T1078 Valid Accounts",
           "what the attacker tries", _my_attack, expect_detection=True,
           attacker_tenant="globex", victim_tenant="acme")
```

Rules: a case returns an `Observation`, never raises for an expected refusal; verdict `breached`
only for a real boundary failure; keep payloads inert and ASCII in source (use `chr()` for
invisible characters, see `corpus.py`); every new case needs a mutation in the test file that
makes it fail.

## Limits

* Development bearer tokens drive the lab, so the **identity provider is out of scope** here; org
  claims on signed OIDC tokens are tested in `tests/security/test_org_isolation.py`.
* In-process transport means TLS, WAF, ingress and network policy are not exercised.
* Findings are as good as the catalogue: a clean campaign shows these 34 attacks fail, not that
  none exist.
