# Breach-and-attack simulation (BAS) and AegisTrace

A controlled harness that attacks the platform's own trust boundaries and records every attempt as
tamper-evident forensic evidence. It answers one question per boundary: *does the control hold,
and did the platform notice?*

> **Nexus Security & AI Lab.** Lab use only. Nothing here runs without the system owner's
> written authorization (see *The authorization gate*), and the only target is the synthetic
> local lab.

```bash
# 0. one-time: the owner authorises in writing (see authorizations/README.md)
python -m art_sim.bas --print-catalogue-digest      # read-only: the digest to review and authorise
cp authorizations/local-lab.template.json authorizations/local-lab.json   # then complete it

# 1. run (refuses with exit code 3 if the authorization is missing, expired or out of scope)
make bas                                            # SQLite lab -> out/bas/{report.md,report.json,aegistrace.jsonl}
python -m art_sim.bas --out out/bas --authorization path/to/auth.json \
       --postgres-dsn postgresql://user@127.0.0.1:5432/scratchdb      # loopback scratch database only
make bas STRICT=1                                   # also fail on defence-in-depth gaps

# 2. read-only, no authorization needed
python -m art_sim.bas --list-scenarios              # == docs/bas-scenarios.md

# 3. verify the forensic log
python scripts/verify_audit_log.py out/bas/aegistrace.jsonl
```

Exit code: `0` no breach · `1` a control failed (or, with `--strict`, a gap remains) ·
`2` unsafe target refused · `3` **not authorised**.

## The authorization gate (no file, no run)

`run_campaign` cannot be called without a `GrantedAuthorization`, and the only way to get one is
`verify_authorization`, which fails closed. The CLI checks it **before** the output directory,
the store or the forensic log exist. The file must state, and the code verifies:

| Requirement | Why |
|---|---|
| a named `authorized_by` and `system_owner` (placeholders such as `<name>`, `TODO`, `PENDING` are rejected) | consent comes from a person, not a template |
| `targets` is exactly `["local-lab"]` — any hostname, URL, address or wildcard invalidates the whole file | real systems are never in scope |
| `backends` within `sqlite` / `postgresql-loopback`, and the backend in use is covered | no remote database, ever |
| `valid_from` / `valid_until` with time zone, at most 90 days apart, and *now* inside the window | authorizations are renewed, not forgotten |
| `catalogue_sha256` equals the digest of the current attack catalogue | adding or changing an attack requires a new, reviewed authorization |
| `acknowledges_lab_only: true` | explicit acknowledgement |

Each campaign writes the authorization (who, until when, file digest, catalogue digest) as the
**first record** of its AegisTrace log. Rejection messages never echo file contents.

**Limits, stated plainly.** This is an *attestation* gate, not cryptographic identity: anyone with
write access to the repository could author the file. The controls around it are procedural —
`authorizations/` and `authorization.py` are owned in `CODEOWNERS`, changes go through review,
and the authorization digest is in every forensic log. For stronger guarantees, sign the file
(signed commit or detached signature) and anchor the log head outside the writer.
`tests/security/test_bas_authorization.py` covers every rejection path; the 12 controls in the
gate were mutation-tested (disabling any one of them makes the tests fail).

## Scenarios, objectives and success criteria

The 34 attack cases are grouped into 10 scenarios. Each states the attacker's **objective**, the
**success criterion** (when the defence is considered effective) and what a failure means — see
[bas-scenarios.md](bas-scenarios.md), generated from the code and kept identical by a test. The
report adds one status per scenario: `held`, `finding` (nothing breached, a gap remains) or `fail`.

## Reproducibility

The campaign fingerprint digests *what was attacked and what happened* (case, verdict, HTTP
status, detail, whether the platform logged it) and excludes run ids, request ids and times. The
SQLite value is committed in `src/art_sim/bas/expected_fingerprint.sha256`; a test compares it
with fresh runs (in process and in independent interpreters from another working directory), and
checks that the fingerprint changes when a control is removed. To reproduce from a clean clone:

```bash
bash scripts/reproduce.sh     # includes the BAS step when authorizations/local-lab.json exists
python -m pytest tests/security/test_bas_reproducibility.py -q
```

## What it is not

* **Not a scanner for real systems.** The only target is an in-process lab (and the authorization gate refuses any other scope): HTTP goes through
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

---
_Nexus Security & AI Lab. Reusable component: it depends on the platform's public API only and carries no customer data._
