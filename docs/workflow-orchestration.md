# Workflow orchestration and recovery

`DurableSimulationWorkflow` reuses the existing typed security engines; it does not
replace them with a generic task runner or an LLM-controlled executor.

```text
allow-listed scenario
  -> ReconAgent -> PlannerAgent -> SupervisorAgent -> mock simulation
  -> deterministic risk and blast radius
  -> normalized remediation + review artifact
  -> optional durable human approval interrupt
  -> in-memory simulated verification
  -> immutable result + Markdown report
```

The planner receives only the sanitizer's allow-listed topology projection. The
supervisor still enforces the Shadow scope and bounded replanning. The execution node is
a mock simulator and the remediation verifier mutates only an immutable in-memory graph
copy. The worker has no cloud, Kubernetes, Terraform, OpenTofu, or shell execution
capability.

## LangGraph checkpoints

Both graphs receive the official async SQLite checkpointer through dependency injection:

- attack workflow thread: `<run_id>:attack`
- remediation/HITL thread: `<run_id>:remediation`

On recovery, the attack graph reads its snapshot and resumes unfinished work or reuses
the completed typed state. The remediation graph pauses at LangGraph's approval
interrupt. Its checkpoint survives process restart.

## Human-in-the-loop resume

The API approval operation performs a durable compare-and-set from
`WAITING_APPROVAL` to `RESUMING` and records the authenticated actor and exact decision.
It then dispatches the run. The worker resumes the matching checkpoint and constructs an
HMAC-bound `ApprovalRecord` from that recorded decision. The proof binds the run,
remediation, actor, decision, and timestamp and is verified before simulated
verification continues.

Concurrent or repeated approval requests cannot replace the first decision. A rejected
decision reaches terminal `REJECTED` and does not create a successful result. HMAC
signing material must be stable across restarts and supplied by a real secret provider
in production; it is never stored in audit metadata or simulation results.

## Failure semantics

Expected topology and approval errors map to stable safe codes. An unexpected exception
is contained only at the worker process boundary and maps to
`WORKFLOW_EXECUTION_FAILED`. Stack traces, filesystem paths, raw prompts, credentials,
and exception messages are not persisted in the API-facing run record.
