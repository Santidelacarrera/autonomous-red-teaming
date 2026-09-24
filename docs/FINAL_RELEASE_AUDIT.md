# FINAL RELEASE AUDIT

## Project

`autonomous-red-teaming`

## Validation Date

2026-09-24 (America/Santiago)

## Release Scope

Phases 1–14 and final release validation. The validated boundary remains defensive,
controlled and `SIMULATION-ONLY`. No real attack, exploit, remediation apply, cloud/IAM/
Kubernetes mutation, credential access, persistence or external deployment was performed.

## Executive Summary

The local source release passed the backend, frontend, static-analysis, dependency-audit,
Shadow E2E, critical concurrency/recovery/security regression, source SBOM and artifact
hash validations. The application process was also started locally against its development
composition: `/health` and `/readiness` returned HTTP 200 with minimal non-sensitive
responses.

Docker 29.8.0 is installed, but its Linux daemon was unavailable. In accordance with the
release procedure, image build, inspection, container startup, image vulnerability scan,
image SBOM and runtime-container checks were not simulated and are `BLOCKED`. Gitleaks was
not installed locally; its CI gate was verified, but the local scan is also `BLOCKED`.

Production remains dependent on externally provisioned broker, server-grade database,
Secret Manager, identity provider, distributed rate limiter, durable audit/SIEM,
telemetry backend and edge infrastructure. No vendor adapter is represented as connected.

## Environment

| Component | Observed value |
| --- | --- |
| OS | Microsoft Windows NT 10.0.26200.0 |
| Python | 3.12.10 |
| pip | 26.2.1 |
| Node.js | v24.11.0 |
| npm | 11.12.1 |
| Docker client | 29.8.0, API 1.56, `desktop-linux` context |
| Docker daemon | Unavailable: `dockerDesktopLinuxEngine` named pipe was not present |

## Test Results

| Validation | Result | Evidence |
| --- | --- | --- |
| Backend | PASS | `.venv\Scripts\python.exe -m pytest -q`: 121 passed in 10.36 s |
| Frontend | PASS | `npm test -- --run`: 19 passed across 7 files in 3.78 s |
| Frontend lint | PASS | `npm run lint` |
| Frontend typecheck | PASS | `npm run typecheck` |
| Frontend production build | PASS | `npm run build`: Vite built 36 modules |
| Ruff | PASS | `.venv\Scripts\python.exe -m ruff check .` |
| Mypy | PASS | `.venv\Scripts\python.exe -m mypy .`: 99 source files |
| pip-audit | PASS | `.venv\Scripts\python.exe -m pip_audit -r requirements.lock`: no known vulnerabilities |
| npm audit | PASS | `npm audit --audit-level=high`: 0 vulnerabilities |
| Shadow E2E | PASS | `.venv\Scripts\python.exe scripts/run_e2e.py`: approved simulated plan and `succeeded` result |
| Critical regressions | PASS | Focused pytest run: 81 concurrency, recovery, persistence, identity, API and worker tests passed in 7.95 s |
| Source SBOM | PASS | CycloneDX Python 1.6 (53 components) and frontend 1.5 (231 components), all with names and versions |
| Artifact hashes | PASS | `var/audit/SHA256SUMS`: 5 entries, 0 mismatches |
| Release configuration integrity | PASS | YAML parsed; 11/11 Actions use full SHAs; 2/2 Docker stages use the verified base digest |
| Gitleaks | BLOCKED | CLI unavailable; commit-pinned `gitleaks-action` gate exists in CI |
| Docker build | BLOCKED | `docker info` exited 1 because the Linux daemon was unavailable |
| Container startup | BLOCKED | No image was built; no container ID was produced |
| Health | PASS | Controlled local process: `GET /health` returned 200 and `{"status":"ok","checks":{"process":"ok"}}` |
| Readiness | PASS | Development composition returned 200 for `operations_store`; controlled production dependency failures return `not_ready` in regression tests |
| Image scan | BLOCKED | CI uses Anchore; no local image/digest existed to scan |
| Image SBOM | BLOCKED | CI uses Anchore SBOM action; no local image/digest existed |

The focused 81-test run is a subset of the 121-test backend suite and is reported as
regression evidence, not as additional tests.

## Docker Validation

| Property | Result |
| --- | --- |
| Dockerfile | Multi-stage `python:3.12.12-slim-bookworm` builder/runtime pinned to manifest-list digest `sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c` |
| Intended validation tag | `autonomous-red-teaming:release-validation` |
| Build | BLOCKED before build by unavailable daemon |
| Image ID/digest/size/timestamp | Not produced |
| Static runtime user | `appuser`, UID/GID 10001 |
| Static exposed port | 8080 |
| Static command | `uvicorn art_sim.api.main:app --host 0.0.0.0 --port 8080` |
| Static healthcheck | HTTP `/health` on port 8080 |
| Static stop signal | `SIGTERM` |
| Container startup/inspection | BLOCKED |
| Container runtime security | BLOCKED |

The Dockerfile and `.dockerignore` statically exclude development dependencies and local
environment files, use the exact runtime lock, and declare a non-root runtime. These are
source observations, not substitutes for image or runtime inspection. The local Uvicorn
process responded correctly, but the Windows PTY did not propagate SIGINT; it was stopped
by its verified PID. Graceful container shutdown therefore remains unvalidated locally.

## Security Validation

- **Authentication:** local signed-fixture tests cover OIDC/JWT signature, allowed
  algorithms, issuer, audience, JWKS behavior and `exp`/`nbf`/`iat`/`sub` claims.
- **Authorization:** RBAC, object-level access and cancellation/approval permissions passed
  the API and identity regression suites.
- **MFA and approval:** MFA claims, approval HMAC, replay rejection, durable CAS and
  concurrent approval behavior passed without real tokens.
- **Worker safety:** duplicate delivery, one-owner leases, fencing, stale worker rejection,
  retry, poison handling, cancellation races, checkpoint recovery and immutable result
  publication passed the focused regression run.
- **API controls:** request validation, pagination, rate-limit behavior, idempotency, safe
  error contracts, no-store behavior and security headers are covered by the passing suite;
  the live `/health` response included `X-Content-Type-Options: nosniff`.
- **Secrets:** `.env` is ignored and untracked. A high-confidence pattern pre-flight found
  no matches in the inspected source/documentation scope. Examples contain placeholders;
  no secret values were printed or loaded for this audit.
- **Audit/telemetry/redaction:** typed event/metric contracts, safe correlation and failure
  redaction passed their tests. Real SIEM and telemetry backends remain external.
- **Container security:** non-root and healthcheck declarations were inspected statically;
  filesystem, capabilities, environment and writable paths could not be validated without
  a running daemon.

The production readiness failure-injection test confirms that database, broker, secret
provider, audit and telemetry outages produce `not_ready` without exposing internal
failure details. Identity and rate-limiter probes remain healthy in that controlled case.

## Supply Chain

### Validated locally

- Exact-version `requirements.lock` and runtime-only `requirements-runtime.lock` exist.
- `frontend/package-lock.json` exists and the npm audit/build/test commands passed.
- Python and frontend CycloneDX documents were regenerated and parsed successfully.
- Every generated component had a name and version.
- SHA-256 evidence for both Python locks, npm lock and both SBOMs had zero mismatches.
- `pip-audit` and `npm audit` reported no known vulnerabilities in this execution.

### Configured, not validated locally

- CI Gitleaks repository scan.
- CI container build.
- CI Anchore vulnerability scan with a high-severity failure cutoff.
- CI Anchore container SBOM generation.
- CI wheel build, source SBOM generation, hashing and artifact upload.
- GitHub build-provenance attestation for release artifacts on `push`.

### Not configured or incomplete

- Hosted provenance execution and independent attestation verification.
- Container-image provenance/publication.
- Python lockfiles use exact versions but do not include download hashes.

The Docker base manifest and every third-party Action are now pinned to immutable digests
or commit SHAs. This prevents silent tag movement but requires an explicit reviewed update
process.

No scanner result, image digest or hosted CI result is claimed without execution evidence.

## Documentation Validation

- `README.md` contains all 29 required sections, the explicit simulation-only boundary,
  real routes/configuration, current test counts and objective production limitations.
- API decorators and `ART_*` settings were compared with their documented counterparts.
- `docs/architecture.md`, `docs/configuration.md`, `docs/threat-model.md`,
  `docs/test-matrix.md` and `docs/production-readiness.md` were reviewed against the code
  and current evidence.
- One GitHub Actions YAML file parsed successfully.
- Local Markdown-link validation reported 0 broken relative links.
- Claim search found no unsupported “production ready”, “enterprise grade”, “100% secure”
  or fictitious production-integration assertion.
- Git hygiene found no tracked `.env`, cache, build output or `var/` evidence file. Existing
  uncommitted Phase 13/14 changes were preserved; no reset, cleanup or commit was performed.

## Findings and Corrections

### Findings

1. Docker Desktop/Linux daemon is unavailable, blocking every image/container validation.
2. Gitleaks CLI is unavailable locally; the scan is configured only as a CI gate.
3. Docker Scout is present but cannot replace the repository's configured Anchore scanner,
   and no image exists to scan.
4. Container SIGTERM behavior, runtime user/capabilities/filesystem and image contents were
   not executable in the current environment.
5. Hosted provenance verification, container provenance and hash-locked Python downloads
   are not complete.
6. Production vendor adapters and external services are not configured or connected.
7. The initial provenance workflow draft granted OIDC/attestation permissions to the
   dependency-build job; least privilege required an isolated post-validation job.

### Corrections performed during this validation

- Regenerated the Python and frontend source SBOMs.
- Regenerated and verified the five-entry SHA-256 artifact manifest.
- Pinned the Python Docker base manifest and all third-party Actions immutably.
- Configured standard GitHub artifact attestations for release artifacts on `push`.
- Isolated `id-token`/attestation permissions in a minimal post-validation provenance job.
- Added this final audit record.

No product-runtime defect was found. The CI least-privilege issue was corrected and its
static regression check passed.

## Known Limitations

The following still require explicit external provisioning, configuration and independent
release evidence:

- Redis Streams, RabbitMQ, Kafka or SQS broker adapter/service;
- PostgreSQL or equivalent server-grade operational store and migrations;
- AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager or Azure Key Vault adapter;
- durable audit/SIEM backend and retention execution;
- OpenTelemetry/Prometheus-compatible backend;
- distributed rate limiter;
- production OIDC tenant/JWKS and client configuration;
- TLS termination, API gateway/WAF and trusted proxy deployment;
- container build, startup, runtime inspection, vulnerability scan and image SBOM;
- server-grade backup/restore drill and recovery evidence;
- deployment automation and operator-approved rollout/rollback;
- multi-region coordination and testing;
- hosted artifact-attestation execution/verification and container provenance;
- hash-complete Python dependency locking.

SQLite, in-process queues and local adapters remain development/single-node components and
are rejected by the production capability boundary.

## Evidence Boundary

Generated local evidence is stored under ignored `var/audit/` paths and is not committed.
The authoritative capability states remain in
[`production-readiness.md`](production-readiness.md), test coverage in
[`test-matrix.md`](test-matrix.md), and security assumptions/residual risks in
[`threat-model.md`](threat-model.md).

# Production Integration Closure

This closure distinguishes a tested application boundary from a concrete adapter and from
a connected backend. No production service was available or emulated as production.

| Capability | Adapter | Real Backend | Validated | Status |
| --- | --- | --- | --- | --- |
| Broker | Provider-neutral ports only; no vendor transport | None | NO | NOT IMPLEMENTED |
| Database | Server-store protocol only; no PostgreSQL implementation/migrations | None | NO | NOT IMPLEMENTED |
| Secrets | Async external-provider protocol only; no managed-service client | None | NO | NOT IMPLEMENTED |
| OIDC | Concrete JWT/JWKS verifier | No production tenant | NO | READY WITH EXTERNAL DEPENDENCY |
| Rate limiting | Distributed port only; process adapter is development-only | None | NO | NOT IMPLEMENTED |
| Audit | Durable sink protocol and typed/redacted events only | None | NO | NOT IMPLEMENTED |
| Telemetry | External sink protocol and bounded vocabulary only | None | NO | NOT IMPLEMENTED |
| Gateway | TLS/proxy/WAF configuration contract and deployment documentation | None | NO | READY WITH EXTERNAL DEPENDENCY |
| Backup | Controlled procedure only | None | NO | READY WITH EXTERNAL DEPENDENCY |
| Deployment | Architecture/runbook only; no production manifest | None | NO | NOT IMPLEMENTED |
| Provenance | GitHub artifact-attestation workflow, commit-pinned | No hosted attestation record | NO | READY WITH EXTERNAL DEPENDENCY |

## Closure evidence

- Docker remains `BLOCKED`: client 29.8.0 is present, Linux daemon is unavailable.
- Gitleaks remains `BLOCKED`: no repository-approved local installation procedure or CLI
  is present; the commit-pinned hosted CI gate is configured.
- The Python base image manifest-list digest was resolved from the registry and pinned in
  both build stages; the image itself was not built.
- All GitHub Actions were resolved to full commit SHAs. Human-readable versions remain in
  comments for controlled updates.
- Failure injection and security/concurrency regressions remain covered by the passing
  121-test backend baseline and the focused 81-test subset recorded above.
- No deployment, migration, restore or external integration test was executed because no
  selected infrastructure or credentials were supplied.

# FINAL RELEASE STATUS

`VALIDATED WITH EXTERNAL DEPENDENCIES`
