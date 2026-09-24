# Project Baseline

> Historical initial baseline. Current Phase 14 evidence is maintained in
> `docs/test-matrix.md` and `docs/production-readiness.md`.

## Date

2026-09-24

## Runtime

- Python: 3.12.10 (`.venv`)
- OS: Windows
- Package manager: pip with Hatchling build backend

## Tests

Baseline command: `.\.venv\Scripts\python.exe -m pytest`

- Total: 26
- Passed: 26
- Failed: 0
- Skipped: 0
- Errors: 0
- Warning: one LangGraph pending-deprecation warning from a third-party package

## Static analysis

- Ruff (`ruff check .`): passed
- Mypy (`mypy .`): passed; 50 source files checked

## Integration

- Neo4j: async official driver through `Neo4jGraphRepository`; safe E2E read succeeded.
- AuraDB: the configured Shadow database was reached by `scripts/run_e2e.py`; this
  run did not seed, mutate, export, apply, or publish any artifact.
- LangGraph: bounded agent graph and checkpointed approval workflow are compiled
  in process; approval uses `MemorySaver` unless a checkpointer is injected.

## Security controls observed

- Shadow graph isolation: deep-copy in-memory graph and regression coverage.
- HITL integrity: required HMAC approval bound to run and remediation.
- Rollback and parallel branches: tested at the in-memory graph boundary.
- Cypher: static, parameterized queries validated before execution.

## Known production gaps

- Persistent LangGraph checkpointing
- Secret-manager composition for `approval_secret`
- Durable `SimulationRun` and audit storage
- Cross-worker concurrency coordination
- Production telemetry backend and structured logging sink
- Deployment, CI/CD and dependency/security scanning automation
