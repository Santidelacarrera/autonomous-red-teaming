# Phases 13 and 14 audit record

Date: 2026-09-24

Overall status: `READY WITH EXTERNAL DEPENDENCY`

## Phase 13 implementation

- Provider-neutral broker settings, health, ack/nack, visibility, backpressure, retry,
  shutdown and safe error taxonomy.
- Server-grade database settings and operational-store health/close contract; SQLite
  remains explicitly single-node.
- Managed-secret provider families, distinct secret references, startup retrieval,
  health/reload/close and fail-closed validation.
- Production dependency configuration for OIDC, broker, database, secrets, audit,
  telemetry, distributed rate limit, TLS and retention.
- Production readiness probes all mandatory dependencies with bounded concurrent timeout;
  liveness remains process-only.
- OIDC now requires `nbf` as well as signature, algorithm, issuer, audience, `exp`, `iat`
  and `sub`.
- Typed audit event vocabulary/retention and operational metric vocabulary/correlation.
- Exact Python runtime/development locks, hardened multi-stage image, SBOM/hash utility and
  CI gates for SBOM, secret scan, container build and vulnerability scan.

No broker, PostgreSQL, Secret Manager, SIEM, OTel, limiter, OIDC tenant, gateway or cloud
deployment is claimed as connected.

## Phase 14 findings

Corrected during the audit:

- production readiness previously checked only the operational store;
- broker failures lacked distinct not-configured/unavailable/operation codes;
- JWT validation did not require `nbf`;
- production dependency configuration and retention were incomplete;
- audit/telemetry vocabularies omitted required operational signals;
- Python had no exact lockfile and Docker installed from ranged dependencies;
- documentation contained obsolete cancellation and production-readiness claims;
- the starting strict Mypy run exposed eight test typing defects, all corrected.

Dependency audits found no known Python or npm vulnerabilities. No real attack, exploit,
remediation apply, cloud/IAM/Kubernetes mutation or external deployment was performed.

## Executed evidence

| Check | Result |
| --- | --- |
| Pytest | PASS — 121 |
| Vitest | PASS — 19 tests / 7 files |
| Ruff | PASS |
| Mypy strict | PASS — 99 files |
| Frontend lint/typecheck/build | PASS |
| `pip-audit -r requirements.lock` | PASS — no known vulnerabilities |
| `npm audit --audit-level=high` | PASS — 0 vulnerabilities |
| Shadow E2E | PASS |
| CycloneDX Python/frontend SBOM + SHA-256 manifest | PASS — `var/audit/` (ignored evidence) |
| Docker build | BLOCKED BY LOCAL ENVIRONMENT — Linux daemon unavailable |
| Container start/health/image scan | NOT EXECUTED — no image was built |
| Local Gitleaks | NOT EXECUTED — CLI unavailable; CI gate configured |

Failure, concurrency and recovery evidence is mapped in [test matrix](test-matrix.md).
Production dependencies and objective states are in
[production readiness](production-readiness.md).
