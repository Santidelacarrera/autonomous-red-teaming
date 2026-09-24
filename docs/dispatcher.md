# Dispatcher and job contract

`SimulationDispatcher` exposes two internal operations:

```text
dispatch(run_id) -> DispatchReceipt
cancel(run_id) -> CancellationReceipt
```

Both are idempotent at the logical run boundary. `cancel()` sends only a cooperative
signal after durable cancellation state has been recorded; it never kills a process.

The broker boundary additionally defines delivery ID/attempt/correlation, receive
timeout, ack, negative ack, delayed retry, visibility extension, pause/resume, health and
graceful close. `BrokerSettings` bounds operation/visibility timeout, in-flight delivery,
delivery attempts and shutdown grace. Adapters must classify failures as
`BROKER_NOT_CONFIGURED`, `BROKER_UNAVAILABLE` or `BROKER_OPERATION_FAILED`; API responses
never contain the underlying exception.

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

No Redis Streams, RabbitMQ, Kafka or SQS connection is implemented in this repository.
