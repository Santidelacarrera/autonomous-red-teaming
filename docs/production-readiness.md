# Production readiness

## Current state

The project is a validated defensive Shadow simulator. The audited baseline has passing
tests, static analysis, and a successful read-only Shadow E2E. It does not apply
infrastructure changes or automatically publish remediation.

## Ready

- Typed input validation and bounded deterministic graph traversal
- In-memory Shadow isolation, rollback and parallel branch regression tests
- HMAC-backed human approval, fail-closed missing secret, and typed lifecycle
- Review-only remediation exporters and simulated post-remediation verification
- Parameterized Cypher validation, retrying async Neo4j/GitHub adapters

## Implemented in this phase

- SQLite WAL operational store with versioned schema migration record, durable run,
  checkpoint, and append-only audit event contracts
- Transactional single-decision approval coordinator for shared SQLite deployments
- Environment-aware operational settings, health/readiness service, and JSON telemetry sink
- Non-root container contract, CI lint/type/test/build/security-scan workflow, and runbooks
- Versioned FastAPI adapter with request correlation, development-only RBAC adapter,
  idempotent run creation, and proposal-only result endpoints

## Needs work

- Managed secret-provider adapter, key rotation execution, and retention policy
- Server-database adapter for multi-node / multi-region coordination
- External telemetry backend, alerting, and production deployment configuration
- Real production authentication/authorization and API gateway rate limiting
- Durable worker orchestration that persists detailed analysis/report results for API reads
- Pinned dependency lockfile, image scan, least-privilege identities, and release provenance

## Blocked

Production multi-process resume is blocked until persistent checkpointing and stable
secret-manager composition exist. Production-grade auditability is blocked until a
durable `SimulationRun` repository is introduced. These are intentionally deferred to
Phase 7; no cloud deployment or persistence backend is added in this phase.
