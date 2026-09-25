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

Docker 29.8.0 and its Linux daemon were validated. The image built, started, passed
container health/readiness, ran as non-root with a read-only root filesystem and zero
capabilities, and shut down cleanly on SIGTERM. The first Bookworm image scan found 16
Critical and 124 High matches. Migrating the pinned base to the current Python
3.13.15/Trixie image eliminated all Critical matches and reduced High matches to 50, but
the configured `high` threshold still fails. The release is therefore `NOT READY`.
Gitleaks was not installed locally; its commit-pinned CI gate was verified, but the local
scan remains `BLOCKED`.

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
| Docker daemon | Docker Desktop 4.92.0; Engine 29.8.0; Linux/amd64; overlayfs |

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
| Artifact hashes | PASS | `var/audit/SHA256SUMS`: 8 entries, 0 mismatches |
| Release configuration integrity | PASS | YAML parsed; 11/11 Actions use full SHAs; 2/2 Docker stages use the verified base digest |
| Gitleaks | BLOCKED | CLI unavailable; commit-pinned `gitleaks-action` gate exists in CI |
| Docker build | PASS | `docker build --pull --tag autonomous-red-teaming:release-validation .` |
| Container startup | PASS | Hardened local containers reached Docker `healthy` |
| Health | PASS | Container `GET /health`: HTTP 200, process `ok`, `no-store`, `nosniff` |
| Readiness | PASS | Development container returned HTTP 200 for `operations_store`; production external dependencies remain absent |
| Image scan | FAIL | Grype 0.119.0: 0 Critical, 50 High, 54 Medium, 9 Low, 44 Negligible; high threshold exited 2 |
| Image SBOM | PASS | Syft 1.52.0, CycloneDX 1.7: 2,941 components, 0 unnamed, 2,941 `bom-ref` values |

The focused 81-test run is a subset of the 121-test backend suite and is reported as
regression evidence, not as additional tests.

## Docker Validation

| Property | Result |
| --- | --- |
| Dockerfile | Multi-stage `python:3.13.15-slim-trixie` builder/runtime pinned to manifest-list digest `sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0` |
| Intended validation tag | `autonomous-red-teaming:release-validation` |
| Build | PASS |
| Image ID | `sha256:e730eeb95a5b66f98e4c29ae0ff3aa72775a836270a0fafe1a2f212194934d72` |
| Image size | 274,938,221 bytes |
| Image timestamp | `2026-09-25T01:29:46.744770729Z` |
| Runtime user | `appuser`, UID/GID 10001 |
| Exposed port | 8080/tcp; published only to loopback during the HTTP test |
| Command | `uvicorn art_sim.api.main:app --host 0.0.0.0 --port 8080` |
| Healthcheck | HTTP `/health` on port 8080; Docker status `healthy` |
| Stop signal | `SIGTERM`; exit 0 in 1.335 seconds; no OOM kill |
| Container startup/inspection | PASS |
| Container runtime security | PASS under the tested hardened invocation |

The runtime was validated with `--read-only`, tmpfs only at `/tmp` and `/app/var`,
`--cap-drop ALL`, `no-new-privileges`, seccomp, PID/memory/CPU limits and no production
credentials. UID/GID were 10001, all effective/bounding capabilities were zero, rootfs
writes were denied, and the two declared tmpfs paths were writable. Image inspection found
no `.env` or credential-named file under `/app`.

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
- **Container security:** validated non-root UID/GID 10001, zero capabilities,
  `NoNewPrivs=1`, seccomp mode 2, read-only rootfs, bounded tmpfs paths, limits, loopback
  publication and graceful SIGTERM exit 0.

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
- The runtime image was built and its metadata, Grype report and Syft CycloneDX SBOM were
  retained under ignored `var/audit/` and included in the eight-entry hash manifest.
- The image SBOM contains 2,791 file components without versions and 150 software
  components with versions; 143 package components have PURLs and all 2,941 components
  have names and `bom-ref` identifiers.
- SBOM-to-lock comparison found all 53 runtime-locked Python packages at the exact versions,
  no missing packages and no version mismatches. The only additional Python distribution
  besides the application itself is base-image `pip`.
- Grype 0.119.0 and Syft 1.52.0 are explicitly versioned in CI.

### Configured, not validated locally

- CI Gitleaks repository scan.
- Hosted CI container build/scan/SBOM execution.
- CI wheel build, source SBOM generation, hashing and artifact upload.
- GitHub build-provenance attestation for release artifacts on `push`.

### Not configured or incomplete

- Hosted provenance execution and independent attestation verification.
- Container-image provenance/publication.
- Python lockfiles use exact versions but do not include download hashes.

The Docker base manifest and every third-party Action are now pinned to immutable digests
or commit SHAs. This prevents silent tag movement but requires an explicit reviewed update
process.

The local scanner result is a failure and is not represented as an accepted risk. No
hosted CI result is claimed without execution evidence.

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

1. The initial Python 3.12.12/Bookworm image contained 16 Critical and 124 High Grype
   matches and failed the configured threshold.
2. Python 3.13.15/Trixie removed every Critical match and reduced High matches to 50, but
   still fails the configured high-severity gate. Of those High matches, 49 have no fix in
   the scanner data and one Python finding points to 3.14.0b1; no risk acceptance exists.
3. Gitleaks CLI is unavailable locally; the scan is configured only as a CI gate.
4. Hosted provenance verification, container provenance and hash-locked Python downloads
   are not complete.
5. Production vendor adapters and external services are not configured or connected.
6. The initial provenance workflow draft granted OIDC/attestation permissions to the
   dependency-build job; least privilege required an isolated post-validation job.

### Corrections performed during this validation

- Regenerated the Python and frontend source SBOMs.
- Regenerated and verified the five-entry SHA-256 artifact manifest.
- Pinned the Python Docker base manifest and all third-party Actions immutably.
- Configured standard GitHub artifact attestations for release artifacts on `push`.
- Isolated `id-token`/attestation permissions in a minimal post-validation provenance job.
- Migrated the container base from Python 3.12.12/Bookworm to the pinned current Python
  3.13.15/Trixie manifest after comparative scans eliminated all Critical findings.
- Built and inspected the image; validated hardened runtime, HTTP probes and SIGTERM.
- Generated a Syft CycloneDX image SBOM and executed the pinned Grype scan.
- Pinned Grype 0.119.0 and Syft 1.52.0 in CI for repeatability.
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
- remediation or formal risk disposition for the 50 unresolved High image findings;
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

- Docker build, startup, health/readiness, runtime hardening, image inspection and graceful
  shutdown are locally `VALIDATED`.
- Gitleaks remains `BLOCKED`: no repository-approved local installation procedure or CLI
  is present; the commit-pinned hosted CI gate is configured.
- The Python 3.13.15/Trixie manifest-list digest is pinned in both build stages; the image
  built and ran successfully.
- Grype failed the release gate with 0 Critical and 50 High matches. Syft produced a valid
  CycloneDX 1.7 image SBOM. The release cannot be promoted without remediation or explicit
  reviewed risk disposition.
- All GitHub Actions were resolved to full commit SHAs. Human-readable versions remain in
  comments for controlled updates.
- Failure injection and security/concurrency regressions remain covered by the passing
  121-test backend baseline and the focused 81-test subset recorded above.
- No deployment, migration, restore or external integration test was executed because no
  selected infrastructure or credentials were supplied.

# FINAL RELEASE STATUS

`NOT READY`
