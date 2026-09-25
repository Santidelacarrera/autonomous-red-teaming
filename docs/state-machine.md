# State machine audit

The durable operational run and the inner remediation flow are distinct typed state
machines.

## Operational simulation run

```text
CREATED -> RUNNING -> SUCCEEDED
                   -> WAITING_APPROVAL -> RESUMING -> RUNNING | SUCCEEDED | REJECTED
                   -> FAILED | REJECTED | CANCELLED
```

`SUCCEEDED`, `FAILED`, `REJECTED`, and `CANCELLED` are terminal. Legacy `COMPLETED` is
also terminal but is not emitted by the Phase 11 worker. Execution ownership is acquired
with transactional compare-and-set and an expiring lease. Approval compare-and-set moves
`WAITING_APPROVAL` to `RESUMING`; it cannot replace or replay the stored decision.

Phase 12 implements cancellation as a durable request. `CREATED` and
`WAITING_APPROVAL` can transition directly to `CANCELLED`; `RUNNING` and `RESUMING`
record the request and a currently fenced worker commits `CANCELLED` at a safe boundary.
Terminal states cannot be cancelled or resurrected.

## Remediation flow

`RemediationLifecycle` is the implemented lifecycle used by `HumanApprovalWorkflow`.

```text
CREATED -> ANALYZING -> REMEDIATION_PENDING -> AWAITING_APPROVAL
AWAITING_APPROVAL -> APPROVED | REJECTED
APPROVED -> APPLIED_SIMULATED -> VERIFYING -> VERIFIED | FAILED
any non-terminal active state -> FAILED
```

`REJECTED`, `VERIFIED`, and `FAILED` are terminal. `APPROVED`,
`APPLIED_SIMULATED`, `VERIFYING`, and `VERIFIED` require an approved
`ApprovalRecord`; `VERIFIED` also requires a verified `VerificationResult`.

The LangGraph attack-planning state is separate: recon -> planner -> supervisor ->
mock simulator, with bounded supervisor replan attempts. Phase 11 persists its official
LangGraph checkpoint under `<run_id>:attack`; it must not be confused with either the
operational run or remediation approval lifecycle.

`HumanApprovalWorkflow.start()` pauses before its approval node. The API performs the
cross-process durable decision CAS; the worker then calls
`resume_recorded_decision()` with exactly that actor and decision. A mismatch or replay
is rejected. The HMAC binds `run_id`, remediation ID, operator, decision, and timestamp.
Restart/resume requires the durable checkpointer and the same injected signing secret.

Before `WAITING_APPROVAL`, the worker atomically persists an immutable review package
containing the normalized countermeasure, generated policy, content SHA-256, baseline
risk/blast radius and a verification preview computed on a graph copy. Production and
local API compositions reject a blind approval when this package is absent. The human
decision also requires a bounded rationale that is persisted with the verified actor.
Automated pre-approval checks artifact integrity, simulation-only scope, path removal,
risk reduction and verification success. A blocked recommendation cannot be approved
through the local or production API; a recommended result still remains pending until a
human reviewer records the final decision for that individual run.
