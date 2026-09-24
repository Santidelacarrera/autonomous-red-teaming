# Operations runbook

## Start

Create a virtual environment, install `.[dev]`, set `ART_SIM_APPROVAL_SECRET` to a
non-empty value of at least 32 bytes, and initialize `SqliteOperationalStore` at the
configured database path before accepting work. Compose `HumanApprovalWorkflow` with
that secret and `sqlite_langgraph_checkpointer()` for a durable native LangGraph saver.
The existing E2E is invoked with
`python scripts/run_e2e.py` and remains Shadow read/simulate only.

## Stop and recovery

Stop accepting new runs first. Finish a short operation or persist a `WorkflowCheckpoint`
and `SimulationRun` status before process termination. Waiting-approval runs are safe to
leave paused; resume requires the same database and signing secret. Do not delete the
SQLite WAL files during recovery.

## Health and logs

`HealthService.health()` is process liveness. `readiness()` runs injected dependency
probes and returns `not_ready` without secrets when a dependency fails. A future HTTP
adapter may map these to `/health` and `/readiness`. `StructuredLoggingTelemetrySink`
emits JSON containing run ID, trace ID, component, status and duration only.

## Failed run / stuck approval

Inspect `SimulationRun`, then list append-only audit events by `run_id`. A waiting run
may be decided once through the coordinator. A rejected, failed, or completed run is
terminal. Do not change rows directly: use a formal recovery event and a new run when
policy requires another simulation.

## Dependency, checkpoint, or secret failure

Readiness remains false for a failed dependency. A missing/corrupt checkpoint raises an
explicit error and must not be resumed. A missing or short approval secret raises
`ConfigurationError`; do not start sensitive workflows. Database recovery is detailed
in [disaster recovery](disaster-recovery.md).
