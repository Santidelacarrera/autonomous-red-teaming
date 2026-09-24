# Worker recovery, leases, and fencing

Every worker acquisition occurs in one store transaction. The store validates the run
state, rejects an active lease, advances `attempt`, creates a monotonically increasing
`fencing_token`, and transitions the run to `RUNNING`.

Every worker-originated mutation validates all three values:

```text
run_id + owner_id + fencing_token
```

The current lease must also remain live. Once a lease expires or another worker obtains
a higher fencing token, the stale worker cannot append stage evidence, publish a result,
fail, reject, wait for approval, or cancel the run. This prevents a paused or partitioned
worker from overwriting a newer generation.

The worker renews its lease at a bounded heartbeat interval. Graceful shutdown stops new
local dispatches and drains active work. `release_execution()` exists for controlled
handoff; an abrupt process death is recovered after lease expiration.

## Recovery

The local recovery scanner activates durable `CREATED`, `RUNNING`, and `RESUMING` runs.
LangGraph state is restored from the official async checkpointer using deterministic
`<run_id>:attack` and `<run_id>:remediation` thread IDs. The operational record,
LangGraph checkpoint, and final result have separate responsibilities.

Attempts are bounded. Exceeding the configured maximum produces:

- terminal `FAILED`;
- safe error code `MAX_ATTEMPTS_EXCEEDED`;
- `simulation.poisoned` evidence;
- a payload-free `PoisonJobRecord` sent through `DeadLetterSink`.

No stack trace, original broker payload, token, credential, or secret is retained in the
dead-letter record.

## Cooperative cancellation

Cancellation is a store CAS, not task termination. An idle `CREATED` or
`WAITING_APPROVAL` run becomes `CANCELLED` immediately. A `RUNNING` or `RESUMING` run
records `cancellation_requested`; its fenced worker observes the flag at safe workflow
boundaries and commits `CANCELLED`. Result publication checks the flag transactionally,
so a cancellation that wins the race prevents artifact publication.
