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

**Update 2026-10-09.** The integrations above that were *implemented* are now *verified* against
real PostgreSQL, Redis, an OpenTelemetry Collector and a Vault server (see the table and
[integrations.md](integrations.md)), and three controls the readiness review asked about —
approval expiry, organization isolation and a tamper-evident audit log — now exist and are
tested. The status line is unchanged on purpose: the dependencies that remain unverified
(a live OIDC tenant that issues a trustworthy organization claim, a production SIEM, a real
monitoring backend, managed databases) are exactly the ones this repository cannot provision.

| Capability | Status | Evidence | External dependency | Validation date |
| --- | --- | --- | --- | --- |
| API and lifecycle | VALIDATED | API/integration tests | No | 2026-09-24 |
| Shadow simulation workflow | VALIDATED | unit + Shadow E2E | Neo4j only for optional E2E | 2026-09-24 |
| OIDC/JWT/RBAC/MFA adapter boundary | READY WITH EXTERNAL DEPENDENCY | concrete JWKS/JWT adapter tests and production rejection tests | Production OIDC tenant/JWKS | 2026-09-24 |
| Local worker | DEVELOPMENT ONLY | restart/recovery/concurrency tests | No | 2026-09-24 |
| Distributed worker contract | READY WITH EXTERNAL DEPENDENCY | message, dispatcher, fencing and poison tests | Broker + worker deployment | 2026-09-24 |
| Broker boundary | READY WITH EXTERNAL DEPENDENCY | provider-neutral contract/config/error tests | Selected broker service | 2026-09-24 |
| Concrete broker adapter | **VERIFIED (real Redis 7.0)** | `RedisStreamsBrokerTransport` + consumer (groups, visibility redelivery, DLQ, DLQ purge): 41 Redis tests green on fakeredis and on a real server | Redis topology/persistence decisions | 2026-10-09 |
| SQLite operational store | DEVELOPMENT ONLY | persistence/concurrency tests | No | 2026-09-24 |
| Server operational-store boundary | READY WITH EXTERNAL DEPENDENCY | protocol, configuration and rejection tests | Selected server database | 2026-09-24 |
| PostgreSQL adapter and migrations | **VERIFIED (real PostgreSQL 16)** | `PostgresOperationalStore` + Alembic: 9 store, 4 migration, 7 retention and 95 lifecycle-integrity cases (both backends) against a real server, locally and as a CI service container; `scripts/run_migrations.py` exercised by the DR drill. Validation found and fixed a multi-statement bug in migration `0001` that would have failed every Helm migration Job | Managed PostgreSQL / pooler / TLS (see docs/integrations.md) | 2026-10-09 |
| Secret-manager boundary | READY WITH EXTERNAL DEPENDENCY | async port, startup validation and redaction tests | Selected managed secret service | 2026-09-24 |
| Concrete managed-secret adapter (mounted) | IMPLEMENTED | `MountedSecretsProvider` (Docker/K8s mounted secrets, path-traversal-safe); tests | Mounted secret volume for deployment | 2026-10-02 |
| Concrete managed-secret adapter (AWS Secrets Manager) | VERIFIED (emulated API) | real `boto3` against `moto`; approval HMAC key resolved from the manager, rotation invalidates old signatures; 9 fake-client tests + 5 moto tests | Live AWS account/region | 2026-10-09 |
| Concrete managed-secret adapter (HashiCorp Vault) | **VERIFIED (real Vault 1.15 dev server)** | 7 tests with the genuine `hvac` client: read, missing path, no-policy token, bogus token, rotation via `reload`, sealed ⇒ not ready, unreachable ⇒ bounded retries; 10 fake-client tests | AppRole/K8s auth, HA, token renewal | 2026-10-09 |
| Distributed rate-limit boundary | READY WITH EXTERNAL DEPENDENCY | port + process-adapter rejection tests | Selected shared limiter | 2026-09-24 |
| Concrete distributed limiter | **VERIFIED (real Redis 7.0)** | `RedisRateLimiter` (atomic Lua sliding window): the same 8 tests on fakeredis and a real server | Redis Cluster/Sentinel/TLS | 2026-10-09 |
| Durable audit boundary | READY WITH EXTERNAL DEPENDENCY | typed/redacted schema and retention contract tests | Selected SIEM/event store | 2026-09-24 |
| Concrete durable audit adapter (local durable file) | VERIFIED | `JsonlDurableSecurityAuditSink` (append-only + fsync) now writes **hash-chained envelopes**; `scripts/verify_audit_log.py` detects gaps, duplicates, edits, reordering, torn writes and (against an anchor) truncation | SIEM log shipper for deployment | 2026-10-09 |
| Concrete durable audit adapter (direct SIEM forward) | VERIFIED (real HTTP, local stand-in) | `SiemForwardAuditSink` over a real socket: HEC framing, auth header, 5xx retry, wrong credentials counted, outage never loses a durable event; loss/duplication reconciliation; fixed a `CancelledError` on every graceful shutdown | A production SIEM (mapping, acks, retention); automated backfill is not implemented | 2026-10-09 |
| Automated data-retention purge job | IMPLEMENTED | `art_sim.retention.job.RetentionJob` + `PostgresOperationalStore` purge methods + `RedisStreamsBrokerTransport.purge_dead_letter`; dry-run by default, audited, Helm `CronJob` (disabled until an operator opts in); 9 unit + 8 integration tests | Live PostgreSQL/Redis for deployment | 2026-10-08 |
| External telemetry boundary | READY WITH EXTERNAL DEPENDENCY | typed metrics/traces and capability rejection tests | Selected OTLP/Prometheus backend | 2026-09-24 |
| Concrete telemetry exporter | **VERIFIED (real OpenTelemetry Collector 0.110.0)** | `OtlpTelemetrySink`: metrics + a span ingested by the Collector (read from its own log) using the repo's `deploy/otel-collector.yaml`; protobuf decoded off a local receiver; 7 in-memory tests. Fixed: readiness reported healthy with the collector down | A real backend behind the Collector; dashboards/alerts | 2026-10-09 |
| Health and readiness | VALIDATED | live local API + multi-dependency failure tests | Real probes supplied by adapters | 2026-09-24 |
| TLS/API gateway/WAF | READY WITH EXTERNAL DEPENDENCY | production config validation + deployment contract | Edge infrastructure | 2026-09-24 |
| Frontend | VALIDATED | 19 Vitest tests, lint, typecheck, build | Production OIDC client configuration | 2026-09-24 |
| Python dependency lock | VALIDATED | `requirements.lock` was incomplete (alembic, SQLAlchemy, boto3, hvac, moto, respx were installed ad hoc); regenerated with `pip-compile` on Python 3.12.15 without changing existing pins. Clean `python:3.12` container, lock only: ruff, mypy, 586 tests pass; `pip-audit`: no known vulnerabilities. `requirements-runtime.lock` unchanged | Lock regeneration tooling | 2026-10-09 |
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
| Backup/restore drill | **EXECUTED — `DR_DRILL_RESULT=PASS`** | `scripts/backup_restore_drill.sh` ran end to end on 2026-10-09 (migrate → seed → `pg_dump` → kill source → isolated restore → row counts, checksum, `alembic_version`). It first failed on a readiness race in the script itself (fixed). Weekly run in `.github/workflows/dr-drill.yml` has still not been observed in hosted CI | Docker + PostgreSQL client tools for the runner | 2026-10-09 |
| Approval review window (expiry) | **IMPLEMENTED + TESTED** | `approval_ttl` checked inside the decision compare-and-set; HTTP 410, `approval.expired`, no state change; production default 24 h. 30 approval-control tests incl. inclusive boundary and a mutation check | Operators must size `ART_APPROVAL_TTL_SECONDS` | 2026-10-09 |
| Organization (tenant) isolation | **IMPLEMENTED + TESTED** — breaking for existing OIDC deployments | verified `org_id` claim; 404 for foreign runs on all 11 run routes (even for a foreign admin); tenant-filtered lists; per-organization idempotency namespace (length bounds preserved); unknown IDs are not mis-audited as tenant probes; 51 tests | **A live IdP that issues a trustworthy organization claim** | 2026-10-09 |
| Tamper-evident audit log | **IMPLEMENTED + TESTED** | hash chain + verifier + SIEM reconciliation; 21 tests | Anchoring the head outside the writer's trust boundary | 2026-10-09 |
| Checkpoint deserialization allow-list | **IMPLEMENTED + TESTED** | allow-list derived from the project's own state modules; removes LangGraph's permissive default; works under `LANGGRAPH_STRICT_MSGPACK=true` | — | 2026-10-09 |
| Lifecycle integrity (invalid transitions change nothing) | **VERIFIED** | every forbidden transition and wrong-state operation leaves all seven tables unchanged, on SQLite and PostgreSQL (95 cases) | — | 2026-10-09 |
| Recovery of an interrupted run from a checkpoint | **VERIFIED** | process killed between graph nodes resumes without repeating work and equals an uninterrupted run; crash after approval applies it once; untrusted checkpoints fail closed | — | 2026-10-09 |
| Laboratory demo | **IMPLEMENTED + REPRODUCIBLE** | `python -m art_sim.demo`: 16/16 live controls, committed findings digest + file hashes (docs/demo.md) | — | 2026-10-09 |
| Clean-clone reproduction | **IMPLEMENTED + EXERCISED** | `scripts/reproduce.sh` run from a fresh `git clone` (docs/reproducibility.md) | Hosted-CI-only gates (Grype, attestation) | 2026-10-09 |
| Multi-region | NOT IMPLEMENTED | no coordination adapter or test environment | Region topology and external services | 2026-09-24 |

## Phase 16 evidence (2026-10-09) — supersedes the Phase 15 caveats below

Phase 15 was produced in a sandbox with no dependencies, no database and no Docker, so most of
its checks were recorded as *NOT EXECUTED*. They have now been executed, from a fresh clone:

| Check | Result |
|---|---|
| Ruff, strict mypy (162 files), Bandit | PASS (Bandit was already failing at the Phase 15 baseline: 2 findings, fixed) |
| `pip-audit -r requirements.lock` | PASS — no known vulnerabilities |
| Backend pytest | PASS — 587 passed, 2 skipped (the two skips are the `from_region`/`from_url` factories, which only apply when the SDK is absent); PostgreSQL 16 and Redis 7 real |
| Same suite in a clean `python:3.12` container, lock only | PASS — 586 passed, 2 skipped (before the Collector/Vault tests were added) |
| Frontend lint, typecheck, 20 Vitest tests, build | PASS |
| Gitleaks over the full git history (v8.18.4, built with Go) | PASS — no leaks |
| Alembic migration chain on real PostgreSQL | PASS — after fixing migration `0001` |
| Backup/restore drill | PASS |
| Container image: build, run read-only/no capabilities/`no-new-privileges`, health, anonymous 401, SIGTERM exit 0 | PASS — built with `OS_UPGRADE=false` because the Debian mirrors are denied by this network's egress policy, so it is **not releasable**; the release build and Grype scan remain hosted-CI gates |
| Helm templates | NOT RENDERED — no `helm` binary here |
| Hosted CI (`ci.yml`, `dr-drill.yml`, attestation, Grype) | NOT OBSERVED from this environment |

## Phase 15 local evidence (historical)

The notes below describe what Phase 15 could and could not run at the time.

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
