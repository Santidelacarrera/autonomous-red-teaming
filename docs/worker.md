# Durable simulation worker

The Phase 11 worker executes a configured Shadow scenario outside the HTTP request
path. `POST /api/v1/simulations` commits a `SimulationRun` first and then asks a
dispatcher to activate it. The durable SQLite record, not the activation message, is
the source of truth.

## Components

| Component | Responsibility |
| --- | --- |
| `SimulationDispatcher` | Accepts an internal `run_id` after the run has been committed. |
| `LocalSimulationDispatcher` | Development-only process queue and recovery scanner. Its declared scope is `PROCESS`. |
| `SimulationWorker` | Claims one run, loads an allow-listed Shadow scenario, executes the workflow, and commits a terminal outcome. |
| `SqliteOperationalStore` | Owns lifecycle compare-and-set, leases, attempt count, audit, and atomic result persistence. |
| `DurableSimulationWorkflow` | Coordinates LangGraph planning, deterministic analysis, HITL, simulated verification, and report rendering. |

The local queue is only a wake-up mechanism. Duplicate messages are expected and safe:
`acquire_execution()` uses a short `BEGIN IMMEDIATE` transaction, lifecycle checks,
and a time-bounded lease so only one worker owns an executable attempt. Terminal runs
cannot be reclaimed or resurrected.

## Execution lifecycle

```text
CREATED -> RUNNING -> SUCCEEDED
                   -> WAITING_APPROVAL -> RESUMING -> SUCCEEDED
                                      \-> RESUMING -> REJECTED
                   -> FAILED | REJECTED | CANCELLED
```

`SUCCEEDED`, `FAILED`, `REJECTED`, and `CANCELLED` are terminal. `COMPLETED` is retained
only as a legacy terminal value. The central `SimulationRunStateMachine` validates
transitions used by the operational store. Phase 12 adds durable cooperative
cancellation and fenced completion; it never terminates a worker thread from the API.

## Recovery and retry policy

At startup and on a bounded polling interval, the local dispatcher enqueues durable
`CREATED`, `RUNNING`, and `RESUMING` records. A live lease prevents concurrent work;
after lease expiry another worker can resume by the same `run_id`. Recovery is capped
by `WorkerSettings.max_recovery_attempts` and records the safe error code
`RECOVERY_ATTEMPTS_EXHAUSTED` when exhausted. There is no unbounded or blind retry.

The attack graph and remediation approval graph use the official LangGraph
`AsyncSqliteSaver`. Checkpoint state is correlated by deterministic thread IDs:
`<run_id>:attack` and `<run_id>:remediation`. The operational tables and LangGraph
checkpoint tables share one SQLite database in development, while retaining distinct
responsibilities.

## Safety and observability

- Only identifiers from the configured scenario allow-list can be dispatched.
- Every scenario validates that all assets belong to the Shadow environment.
- `ShadowGraphRepository` is read-only; all write methods fail closed.
- Unknown worker failures persist only `WORKFLOW_EXECUTION_FAILED`, never exception text.
- Stage events carry `run_id` and `trace_id`; secrets and raw untrusted payloads are not
  included.
- Counters and duration observations cover starts, waits, successes, failures, total
  duration, and workflow-stage duration.

## Deployment boundary

`LocalSimulationDispatcher` is suitable for development and single-process operation
only. Production composition rejects it and requires an externally supplied dispatcher
whose declared scope is `DISTRIBUTED`, plus independently deployed worker processes and
a server-grade operational store. `BrokerSimulationDispatcher` provides the transport
boundary and versioned message; no broker, cloud queue, or vendor service is represented
as connected by this repository.
