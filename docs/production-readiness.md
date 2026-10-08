# Production readiness

## Objective status

The platform remains `SIMULATION-ONLY`. The application contracts and fail-closed
composition are implemented, while mandatory production services are deployment-owned
and are not represented as connected. Overall status:

`NOT READY — pending external infrastructure only` (validated end-to-end: the production composition starts in a hardened container with PostgreSQL, Redis broker, rate limiter, mounted secrets, durable audit and OTLP telemetry all reporting ready; only a live OIDC tenant is required for full readiness)

Reason: every application-side adapter now has a concrete implementation (Redis limiter,
Redis Streams broker, PostgreSQL store, OTLP telemetry, durable audit, mounted secrets),
but production still requires those adapters to be connected to LIVE vendor services and an
external TLS edge / real OIDC tenant, which are deployment-owned and not provisioned in this
repository. The container image scan passes the `high` gate (0 fixable High/Critical).

| Capability | Status | Evidence | External dependency | Validation date |
| --- | --- | --- | --- | --- |
| API and lifecycle | VALIDATED | API/integration tests | No | 2026-09-24 |
| Shadow simulation workflow | VALIDATED | unit + Shadow E2E | Neo4j only for optional E2E | 2026-09-24 |
| OIDC/JWT/RBAC/MFA adapter boundary | READY WITH EXTERNAL DEPENDENCY | concrete JWKS/JWT adapter tests and production rejection tests | Production OIDC tenant/JWKS | 2026-09-24 |
| Local worker | DEVELOPMENT ONLY | restart/recovery/concurrency tests | No | 2026-09-24 |
| Distributed worker contract | READY WITH EXTERNAL DEPENDENCY | message, dispatcher, fencing and poison tests | Broker + worker deployment | 2026-09-24 |
| Broker boundary | READY WITH EXTERNAL DEPENDENCY | provider-neutral contract/config/error tests | Selected broker service | 2026-09-24 |
| Concrete broker adapter | IMPLEMENTED | `RedisStreamsBrokerTransport` + consumer (groups, visibility redelivery, DLQ); 10 tests | Live Redis for deployment | 2026-10-02 |
| SQLite operational store | DEVELOPMENT ONLY | persistence/concurrency tests | No | 2026-09-24 |
| Server operational-store boundary | READY WITH EXTERNAL DEPENDENCY | protocol, configuration and rejection tests | Selected server database | 2026-09-24 |
| PostgreSQL adapter and migrations | IMPLEMENTED | `PostgresOperationalStore` (asyncpg, FOR UPDATE row locks) + versioned Alembic migrations (`migrations/`, `scripts/run_migrations.py`, Helm pre-upgrade hook); 9 store + 4 migration integration tests vs real PostgreSQL | Live PostgreSQL for deployment | 2026-10-08 |
| Secret-manager boundary | READY WITH EXTERNAL DEPENDENCY | async port, startup validation and redaction tests | Selected managed secret service | 2026-09-24 |
| Concrete managed-secret adapter (mounted) | IMPLEMENTED | `MountedSecretsProvider` (Docker/K8s mounted secrets, path-traversal-safe); tests | Mounted secret volume for deployment | 2026-10-02 |
| Concrete managed-secret adapter (AWS Secrets Manager) | IMPLEMENTED | `AwsSecretsManagerProvider` (bounded retry on throttling, fail-closed on not-found/denied); 9 tests against a fake boto3-shaped client | Live AWS account/region + `boto3` installed for deployment | 2026-10-08 |
| Concrete managed-secret adapter (HashiCorp Vault) | IMPLEMENTED | `VaultSecretProvider` (KV v2, seal-aware health check, bounded retry); 10 tests against a fake hvac-shaped client | Live Vault cluster + `hvac` installed for deployment | 2026-10-08 |
| Distributed rate-limit boundary | READY WITH EXTERNAL DEPENDENCY | port + process-adapter rejection tests | Selected shared limiter | 2026-09-24 |
| Concrete distributed limiter | IMPLEMENTED | `RedisRateLimiter` (atomic Lua sliding window); 8 tests incl. concurrency/rollover via fakeredis | Live Redis for deployment | 2026-10-02 |
| Durable audit boundary | READY WITH EXTERNAL DEPENDENCY | typed/redacted schema and retention contract tests | Selected SIEM/event store | 2026-09-24 |
| Concrete durable audit adapter (local durable file) | IMPLEMENTED | `JsonlDurableSecurityAuditSink` (append-only + fsync); tests | SIEM log shipper for deployment | 2026-10-02 |
| Concrete durable audit adapter (direct SIEM forward) | IMPLEMENTED | `SiemForwardAuditSink` (durable local write-through + bounded-queue, retried, best-effort HTTP forward to a SIEM/HEC endpoint; never loses an event to a SIEM outage); 10 tests against a fake async HTTP client | Live SIEM HTTP ingestion endpoint for deployment | 2026-10-08 |
| Automated data-retention purge job | IMPLEMENTED | `art_sim.retention.job.RetentionJob` + `PostgresOperationalStore` purge methods + `RedisStreamsBrokerTransport.purge_dead_letter`; dry-run by default, audited, Helm `CronJob` (disabled until an operator opts in); 9 unit + 8 integration tests | Live PostgreSQL/Redis for deployment | 2026-10-08 |
| External telemetry boundary | READY WITH EXTERNAL DEPENDENCY | typed metrics/traces and capability rejection tests | Selected OTLP/Prometheus backend | 2026-09-24 |
| Concrete telemetry exporter | IMPLEMENTED | `OtlpTelemetrySink` (OpenTelemetry metrics+traces); 7 tests via in-memory OTel exporters | OTLP collector for deployment | 2026-10-02 |
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
| Container vulnerability scan | VALIDATED | Grype 0.119.0: 0 fixable High/Critical after runtime `apt-get upgrade`; only-fixed gate passes | Documented disposition in .grype.yaml | 2026-10-02 |
| Signed provenance (release artifacts) | READY WITH EXTERNAL DEPENDENCY | commit-pinned GitHub artifact-attestation step configured for pushes | Hosted workflow identity and retained attestation | 2026-09-24 |
| Signed provenance (container image) + independent verification | IMPLEMENTED (configured; unexecuted locally) | `container` pushes the scanned image to GHCR by digest; `attest-container` attests that exact digest; `verify-container-provenance` (a separate job/permission context) and `scripts/verify_image_provenance.py` independently re-verify it via `gh attestation verify` before promotion | Hosted GitHub Actions run (this cannot be minted or verified from a local sandbox) | 2026-10-08 |
| TLS edge configuration | IMPLEMENTED (configured; unexecuted locally) | Helm `ingress.yaml` (cert-manager annotations, disabled by default) + `deploy/edge/` Caddy overlay for docker-compose, both documented in `docs/tls-edge.md` | Ingress controller + cert-manager, or ACME reachability, for deployment | 2026-10-08 |
| Deployment automation | IMPLEMENTED | Helm chart (lint+template+hardening-asserted) + docker-compose.prod; production composition root `art_sim.api.serve` | Target cluster/registry | 2026-10-02 |
| Backup/restore drill | IMPLEMENTED (executable; scheduled, not yet run in hosted CI) | `scripts/backup_restore_drill.sh` runs the documented backup/kill/restore/verify procedure against two disposable PostgreSQL containers it creates itself; `.github/workflows/dr-drill.yml` runs it weekly | Docker + PostgreSQL client tools for the runner | 2026-10-08 |
| Multi-region | NOT IMPLEMENTED | no coordination adapter or test environment | Region topology and external services | 2026-09-24 |

## Phase 15 local evidence

Phase 15 added the AWS Secrets Manager and HashiCorp Vault secret adapters, the direct-
SIEM-forward audit sink, versioned PostgreSQL migrations, the automated data-retention
purge job, the executable backup/restore drill, TLS edge configuration, and independent
container-provenance verification. This work was done in a network-restricted sandbox that
could reach neither PyPI (to install `boto3`/`hvac`/`moto`/`alembic`/`sqlalchemy`/`respx` or
regenerate `requirements.lock`) nor a live PostgreSQL/Redis/GitHub-Actions runner, so the
evidence below is deliberately narrower than Phase 14's and should not be read as
equivalent to it.

| Check | Result |
| --- | --- |
| Ruff (`ruff check .`), whole repository | PASS |
| `python -m py_compile` on every new/changed `.py` file | PASS |
| Backend Pytest (new suites) | NOT EXECUTED — this sandbox has none of the project's core dependencies installed (no `pydantic`/`fastapi`/`pytest`/`asyncpg` in its Python, and no PyPI reachability to install them); the new tests are designed to need no live PostgreSQL/Redis/SIEM and no `boto3`/`hvac` (hand-written fakes), so they are expected to pass under the hosted CI's existing Postgres service, but that expectation is unverified here |
| Mypy strict | NOT EXECUTED — same dependency gap; `[[tool.mypy.overrides]]` entries were added for `boto3`/`hvac`/`alembic`/`sqlalchemy` so a dependency-complete run does not fail on missing stubs |
| Alembic migration chain (`tests/integration/test_postgres_migrations.py`) | NOT EXECUTED locally (no reachable PostgreSQL); logic reviewed against `migrations/env.py`'s DSN-resolution order and `alembic`'s async-engine API |
| Backup/restore drill (`scripts/backup_restore_drill.sh`) | NOT EXECUTED locally (no Docker daemon in this sandbox); `bash -n` syntax-checked |
| Helm templates (`ingress.yaml`, `migration-job.yaml`, `retention-cronjob.yaml`) | NOT RENDERED — no `helm` binary available in this sandbox; checked for balanced `{{ }}` and reviewed against the existing `deployment.yaml` conventions |
| `requirements.lock` | UNCHANGED — the new optional adapters' dependencies are declared in `pyproject.toml`'s extras but are not yet in the resolved lock graph; CI installs `alembic`/`sqlalchemy` ad hoc until the lock is regenerated with PyPI access (see `docs/supply-chain.md`) |

None of the above should be taken as "VALIDATED" in the sense the rest of this table uses
that word. Before this work is merged, an environment with real dependencies and a live
PostgreSQL/Redis must run `make check`, the new integration tests, and the DR drill, and
the hosted `ci.yml`/`dr-drill.yml` workflows must run at least once each.

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
