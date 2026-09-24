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
- Separate production DI composition with strict OIDC/MFA configuration and startup
  capability checks for distributed rate limiting and durable security audit
- Central security-audit redaction and explicit MFA-failure evidence
- Durable simulation worker with SQLite execution CAS, leases, bounded recovery,
  official LangGraph checkpoint resume, and immutable result commits
- Restart-safe HITL decisions and real persisted result endpoints
- Frontend lifecycle polling with terminal stop and bounded transient-error backoff
- Versioned broker jobs, distributed dispatcher/consumer ports, fencing tokens,
  lease heartbeat, safe poison-job records, and cooperative cancellation
- Declarative capability checks that reject SQLite, local dispatch, environment-only
  secrets, volatile audit, process limiting, and process telemetry in production

## Needs work

- Managed secret-provider adapter, key rotation execution, and retention policy
- Server-database adapter for multi-node / multi-region coordination
- External telemetry backend, alerting, and production deployment configuration
- Concrete IdP tenant/client configuration and distributed rate-limiter adapter
- Durable immutable security-audit/SIEM adapter and its retention policy
- Distributed broker/dispatcher and independently deployed production worker runtime
- Server-grade execution, checkpoint, and result persistence for multi-replica workers
- Pinned dependency lockfile, image scan, least-privilege identities, and release provenance

## Production composition status

- **IMPLEMENTED:** `create_production_app(...)`, strict OIDC/JWKS verifier, HTTPS CORS,
  HSTS, explicit secret resolution, fail-closed dependency capability validation, and
  rejection of a missing or process-local worker dispatcher.
- **READY WITH EXTERNAL DEPENDENCY:** real distributed limiter, durable audit sink,
  managed secret provider, server operational store, distributed dispatcher/worker,
  external telemetry, IdP configuration, and TLS edge.
- **NOT IMPLEMENTED:** those vendor-specific adapters, multi-region coordination,
  immutable retention service, cooperative cancellation, or cloud deployment automation.

The existence of production contracts does not make this repository production-ready.
SQLite remains a documented single-node option and must not be presented as a
multi-replica operational database.
