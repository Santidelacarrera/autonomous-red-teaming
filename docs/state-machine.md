# State machine audit

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
mock simulator, with bounded supervisor replan attempts. It has no persisted lifecycle
model yet and must not be confused with the remediation approval lifecycle.

`HumanApprovalWorkflow.start()` pauses before its approval node. `decide()` accepts
exactly one pending decision per `run_id` in the same process; a second decision is
rejected. The HMAC binds `run_id`, remediation ID, operator, decision, and timestamp.
Restart/resume requires an injected durable checkpointer and the same injected signing
secret. Cross-process compare-and-set remains a Phase 7 concern.
