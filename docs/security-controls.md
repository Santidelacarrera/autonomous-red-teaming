# Security controls — what is enforced, and where each is proven

Each control lists the mechanism and the tests that prove it **both ways**: the legitimate path
works (positive) and every way of abusing it fails (negative). All run against synthetic Shadow
data in an authorized, local environment; nothing here touches a real system.

Files: `tests/security/test_approval_controls.py` (AC), `test_org_isolation.py` (OI),
`test_audit_integrity.py` (AI), `tests/integration/test_state_integrity.py` (SI),
`test_checkpoint_recovery.py` (CR), `tests/unit/test_checkpoint_serde.py` (CS).

## 1. High-impact actions require a valid human approval

| Mechanism | Positive | Negative |
|---|---|---|
| The worker pauses at `WAITING_APPROVAL`; nothing is applied or published before a decision. Result endpoints answer 409 until a human decides. | AC: operator approval inside the window → 200, audited; demo shows result 200 only after approval | OI/demo: result read before approval → 409; AC: approving a run that is not waiting → 409 |
| **Review window** (`approval_ttl`, default 24 h in production, `ART_APPROVAL_TTL_SECONDS`): evaluated **inside the same transaction as the decision compare-and-set**, so there is no check-then-act gap. An expired decision → HTTP 410 `APPROVAL_EXPIRED`, an `approval.expired` audit event, and *no* state change. The run is not auto-approved; it can still be cancelled. | AC: exactly at the TTL is accepted (inclusive boundary) | AC: one microsecond later → 410; approve *and* reject both refused; every table unchanged; `ApprovalExpiredError` is still an `ApprovalRequiredError` so existing fail-closed handlers apply |
| **HMAC proof** binds run ID, remediation, operator, decision and timestamp; the worker re-verifies it before applying anything. | AC: valid proof unlocks simulated verification; recovered idempotently with the same secret | AC: empty/zero/non-hex/uppercase signatures; missing proof or record; swapped operator, shifted timestamp, swapped remediation; **a rejection flipped into an approval**; a proof **replayed onto another run**; a rotated or foreign secret; secrets < 32 bytes refused |
| **Replay**: one decision per run; the first is final. | AC: first approval recorded | AC: exact replay and a conflicting second operator → 409, run byte-identical, one approval event; SI: a second `decide` cannot replace the first |
| **Permissions**: `simulation:approve`/`reject` (operator, admin); MFA step-up when configured; pre-approval gate blocks candidates that fail automated checks. | AC/OI: operator and admin approve | AC/OI: viewer approve **and** reject → 403, run unchanged; anonymous and malformed credentials → 401; short reason / unknown decision / extra field → 422 |

## 2. Access control by organization and role

| Mechanism | Positive | Negative |
|---|---|---|
| `organization_id` comes **only** from the verified credential (OIDC claim `org_id`, or `ART_OIDC_ORGANIZATION_CLAIM`). Absent or malformed → authentication fails (fail-closed); a single-tenant fallback must be opted into explicitly (`ART_OIDC_DEFAULT_ORGANIZATION`). It is never read from a header, query or body. | OI: claim honored; custom claim name honored; explicit single-tenant fallback; owning org keeps full access | OI: missing claim; `""`, `../acme`, spaces, 65 chars, numbers, lists, objects → rejected; `X-Organization`, `?organization_id=` and a body field cannot override it (body field → 422) |
| **Tenant mediation on every `{run_id}` route** (11 routes): the run must belong to the caller's organization, otherwise **404**, indistinguishable from a missing run, plus an audited `authorization.denied`. | OI: owner reads, lists, approves | OI: a foreign **administrator** (holds every permission) is refused on all 11 routes and the run is unchanged; foreign and missing runs return identical bodies; the probe is audited with the subject; a merely *unknown* ID is an ordinary 404 and is **not** recorded as a denial; idempotency-key length bounds still hold after namespacing |
| Listing is tenant-filtered in SQL (SQLite and PostgreSQL), composed with status filters and pagination. Idempotency keys are namespaced per organization (otherwise tenant B reusing A's key would receive A's run). | OI: pages contain only the caller's runs | OI: no foreign runs on any page; the same `Idempotency-Key` in two orgs creates two runs |
| **Roles inside the organization**: viewer reads; operator also creates/approves/cancels; admin also reads the audit trail and security status. | OI: role matrix for create, approve, audit, security status | OI: viewers never mutate; viewer/operator → 403 on audit and security status; the role check precedes the tenant check, so a viewer learns nothing about foreign runs |

## 3. Failure recovery, and detection of lost or duplicated events

| Mechanism | Proven by |
|---|---|
| **Interrupted run resumes from its checkpoint** without repeating finished work, and ends identical to an uninterrupted run. | CR: process killed between two graph nodes; recon runs once; result digest equals a control run. Crash after the approval was applied → applied exactly once. |
| **Untrusted checkpoints fail closed.** Wiped checkpoint after a decision, or a different signing secret → the run does not succeed and publishes nothing. LangGraph's permissive deserialization is replaced by an **allow-list** derived from the project's own state modules. | CR (wiped, rotated secret); CS: allow-listed state round-trips exactly; an unlisted pydantic model or enum is returned as inert data, never instantiated; works under `LANGGRAPH_STRICT_MSGPACK=true` |
| **Invalid transitions do not modify persisted state.** | SI: all forbidden `(source, target)` pairs, plus wrong-state `decide`, stale/foreign fencing, claiming non-executable runs, resurrecting terminal runs, unknown runs, duplicate run IDs, rebinding an idempotency key — raw snapshot of seven tables unchanged, on SQLite **and** PostgreSQL |
| **Audit log is tamper-evident**: each line is a hash-chained envelope (`seq`, `prev`, `hash`). `scripts/verify_audit_log.py` finds **gaps, duplicate `seq`/`event_id`, edited events, reordering, torn writes** and — against an externally held head — **truncation**. | AI: each failure mode, plus restart and 80 concurrent appends keep a valid chain; a torn write is isolated and the chain continues without a gap |
| **SIEM loss/duplication** is detectable by reconciling event IDs against the durable log. | AI: a flaky SIEM that loses two events and duplicates one is reported precisely (`missing`, `duplicated`) while the durable record stays intact |

**Honest limits.** A hash chain proves integrity, not authenticity: someone who can rewrite the
*whole* file can rebuild a consistent chain, so anchor the head outside the writer's trust
boundary (SIEM, object-lock bucket). The JSONL sink is the **single writer** of its file. The
forwarder is at-least-once with a bounded queue and has no automatic backfill yet. HMAC protects
the checkpointed approval; it does not make a compromised database trustworthy.
