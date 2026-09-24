# Dispatcher and job contract

`SimulationDispatcher` exposes two internal operations:

```text
dispatch(run_id) -> DispatchReceipt
cancel(run_id) -> CancellationReceipt
```

Both are idempotent at the logical run boundary. `cancel()` sends only a cooperative
signal after durable cancellation state has been recorded; it never kills a process.

## SimulationJobV1

The strict Pydantic message contains only:

- contract and message version;
- message and run identifiers;
- workflow version and allow-listed scenario identifier;
- expected durable attempt;
- original run creation time;
- bounded correlation identifier.

Unknown versions, extra fields, oversized payloads, incompatible run metadata, stale
attempts, terminal runs, and unconfigured scenarios are rejected. Passwords, tokens,
cookies, request headers, raw prompts, and credentials are not fields in the contract.

## Retry policy

`RetryPolicy` implements bounded exponential backoff and jitter. Only an explicit
`TransientAdapterError` is retried. Validation, authorization, state, integrity, and
contract errors are not retried. The broker adapter and operational telemetry delivery
use this policy; a real server-store adapter must classify its own transient database
errors under the same contract.
