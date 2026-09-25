# Production readiness

## Objective status

The platform remains `SIMULATION-ONLY`. The application contracts and fail-closed
composition are implemented, while mandatory production services are deployment-owned
and are not represented as connected. Overall status:

`NOT READY`

Reason: the local pinned Grype scan found 50 High vulnerabilities and failed the
repository's `high` release threshold. There are no remaining Critical matches after the
base-image migration, but no approved risk disposition exists for the High findings.

| Capability | Status | Evidence | External dependency | Validation date |
| --- | --- | --- | --- | --- |
| API and lifecycle | VALIDATED | API/integration tests | No | 2026-09-24 |
| Shadow simulation workflow | VALIDATED | unit + Shadow E2E | Neo4j only for optional E2E | 2026-09-24 |
| OIDC/JWT/RBAC/MFA adapter boundary | READY WITH EXTERNAL DEPENDENCY | concrete JWKS/JWT adapter tests and production rejection tests | Production OIDC tenant/JWKS | 2026-09-24 |
| Local worker | DEVELOPMENT ONLY | restart/recovery/concurrency tests | No | 2026-09-24 |
| Distributed worker contract | READY WITH EXTERNAL DEPENDENCY | message, dispatcher, fencing and poison tests | Broker + worker deployment | 2026-09-24 |
| Broker boundary | READY WITH EXTERNAL DEPENDENCY | provider-neutral contract/config/error tests | Selected broker service | 2026-09-24 |
| Concrete broker adapter | NOT IMPLEMENTED | no Redis Streams/RabbitMQ/Kafka/SQS transport module | Provider selection and integration environment | 2026-09-24 |
| SQLite operational store | DEVELOPMENT ONLY | persistence/concurrency tests | No | 2026-09-24 |
| Server operational-store boundary | READY WITH EXTERNAL DEPENDENCY | protocol, configuration and rejection tests | Selected server database | 2026-09-24 |
| PostgreSQL adapter and migrations | NOT IMPLEMENTED | no concrete pool/store or migration package | PostgreSQL service and integration environment | 2026-09-24 |
| Secret-manager boundary | READY WITH EXTERNAL DEPENDENCY | async port, startup validation and redaction tests | Selected managed secret service | 2026-09-24 |
| Concrete managed-secret adapter | NOT IMPLEMENTED | no AWS/Vault/GCP/Azure client adapter | Provider selection and workload identity | 2026-09-24 |
| Distributed rate-limit boundary | READY WITH EXTERNAL DEPENDENCY | port + process-adapter rejection tests | Selected shared limiter | 2026-09-24 |
| Concrete distributed limiter | NOT IMPLEMENTED | no Redis/gateway/proxy adapter | Shared backend or edge service | 2026-09-24 |
| Durable audit boundary | READY WITH EXTERNAL DEPENDENCY | typed/redacted schema and retention contract tests | Selected SIEM/event store | 2026-09-24 |
| Concrete durable audit adapter | NOT IMPLEMENTED | no SIEM/event-store client adapter | Audit backend and retention service | 2026-09-24 |
| External telemetry boundary | READY WITH EXTERNAL DEPENDENCY | typed metrics/traces and capability rejection tests | Selected OTLP/Prometheus backend | 2026-09-24 |
| Concrete telemetry exporter | NOT IMPLEMENTED | no OTLP/Prometheus exporter composition | Collector/backend | 2026-09-24 |
| Health and readiness | VALIDATED | live local API + multi-dependency failure tests | Real probes supplied by adapters | 2026-09-24 |
| TLS/API gateway/WAF | READY WITH EXTERNAL DEPENDENCY | production config validation + deployment contract | Edge infrastructure | 2026-09-24 |
| Frontend | VALIDATED | 19 Vitest tests, lint, typecheck, build | Production OIDC client configuration | 2026-09-24 |
| Python dependency lock | VALIDATED | `requirements.lock`, `requirements-runtime.lock` | Lock regeneration tooling | 2026-09-24 |
| npm dependency lock | VALIDATED | `frontend/package-lock.json`, tests/build/audit | npm registry during build | 2026-09-24 |
| Source SBOM and artifact hashes | VALIDATED | regenerated CycloneDX documents + 5 verified SHA-256 entries | No | 2026-09-24 |
| Immutable Docker base reference | VALIDATED | Python 3.13.15/Trixie manifest-list digest resolved, pinned and built | Registry availability during build | 2026-09-24 |
| Immutable GitHub Action references | VALIDATED | every `uses:` entry pinned to a resolved full commit SHA | GitHub Actions availability | 2026-09-24 |
| Container image build | VALIDATED | local pinned multi-stage build; image `sha256:e730eeb95a5b66f98e4c29ae0ff3aa72775a836270a0fafe1a2f212194934d72` | No | 2026-09-24 |
| Container runtime hardening | VALIDATED | UID 10001, read-only rootfs, zero capabilities, no-new-privileges, seccomp, limits and SIGTERM exit 0 | Orchestrator must reproduce the tested flags | 2026-09-24 |
| Container image SBOM | VALIDATED | Syft 1.52.0 CycloneDX 1.7, 2,941 named components and 2,941 `bom-ref` values | No | 2026-09-24 |
| Container vulnerability scan | BLOCKED | Grype 0.119.0 executed: 0 Critical, 50 High; high threshold failed | Remediation or reviewed risk disposition | 2026-09-24 |
| Signed provenance | READY WITH EXTERNAL DEPENDENCY | commit-pinned GitHub artifact-attestation step configured for pushes | Hosted workflow identity and retained attestation | 2026-09-24 |
| Deployment automation | NOT IMPLEMENTED | no cloud/Kubernetes/Compose production manifest or apply workflow | Selected platform and operator approval | 2026-09-24 |
| Backup/restore drill | READY WITH EXTERNAL DEPENDENCY | controlled procedure documented, not executed server-side | Server database, broker and audit backends | 2026-09-24 |
| Multi-region | NOT IMPLEMENTED | no coordination adapter or test environment | Region topology and external services | 2026-09-24 |

## Phase 14 local evidence

| Check | Result |
| --- | --- |
| Backend Pytest | PASS — 122 tests |
| Frontend Vitest | PASS — 20 tests in 8 files |
| Ruff | PASS |
| Mypy strict | PASS — 97 source files |
| Frontend lint/typecheck/build | PASS |
| `pip-audit -r requirements.lock` | PASS — no known vulnerabilities |
| `npm audit --audit-level=high` | PASS — 0 vulnerabilities |
| Shadow E2E | PASS |
| Local Python/frontend SBOM + SHA-256 manifest | PASS — generated under ignored `var/audit/` |
| Docker build/start/health/SIGTERM | PASS — hardened image started healthy and exited 0 |
| Local image scan | FAIL — Grype 0.119.0 found 0 Critical and 50 High; threshold `high` exited 2 |
| Local image SBOM | PASS — Syft 1.52.0, CycloneDX 1.7, 2,941 components |
| Local Gitleaks | NOT EXECUTED — CLI unavailable; hosted CI gate configured |
| Hosted CI container job | NOT EXECUTED — local build/SBOM passed and local scan failed |

Counts and results above must be updated whenever the suite changes; they are not a
service-level guarantee.
