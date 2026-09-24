# API architecture and state synchronization

```text
HTTP -> FastAPI router -> Application service -> SqliteOperationalStore
                                      |               |
                                      |               +-> SimulationRun / audit / idempotency
                                      +-> worker orchestration -> LangGraph checkpoint -> analysis outputs
```

`SimulationRun` is the durable external source of truth for API lifecycle state. A
LangGraph thread uses the same opaque `run_id` as its `thread_id`. A worker must update
the run and append audit evidence after each durable workflow boundary; it must persist
the native checkpoint before reporting a waiting or recoverable state.

Creation is intentionally asynchronous: `POST` only persists `created` and returns 202.
It does not claim that graph analysis has happened. If worker startup fails, orchestration
must set `SimulationRun.status=failed` and append `simulation.failed`; it must never
return an analysis result as successful. The current API deliberately returns conflict
for detailed results not yet persisted, rather than re-running graph analysis in a GET.

Approval is delegated to the same SQLite compare-and-set that owns durable run state.
The endpoint cannot set scores, verification status, artifacts, or lifecycle values. A
server database adapter is needed before multi-node/multi-region workers share this
responsibility.
