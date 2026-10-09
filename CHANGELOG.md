# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking
- **Organization (tenant) isolation.** OIDC tokens must now carry a verified organization claim
  (`org_id`, or `ART_OIDC_ORGANIZATION_CLAIM`); a token without it is rejected. Deployments that
  do not issue the claim must opt in explicitly with `ART_OIDC_DEFAULT_ORGANIZATION=<id>`.
  Run records gain `organization_id` (rows written before this default to `default`).
  Idempotency keys are now namespaced per organization, so a client retrying a request created
  *before* the upgrade may create one new run.
- The durable security-audit file is now hash-chained envelopes (`seq`, `prev`, `hash`, `event`).
  Readers accept the previous one-event-per-line format; new lines are chained.

### Fixed
- **Migration `0001` failed on PostgreSQL**: seven `CREATE TABLE` in one statement are rejected
  by asyncpg, so the Helm migration Job could never have succeeded.
- `SiemForwardAuditSink.close()` raised `CancelledError` on every graceful shutdown.
- OTLP telemetry readiness reported healthy with the collector unreachable.
- `scripts/backup_restore_drill.sh` raced the PostgreSQL image's temporary init server.
- `migrations/env.py` disabled every other logger in the process.
- CI gates that were red: strict mypy (5 errors) and Bandit (2 findings).

### Added (2026-10-09 validation pass)
- **Approval review window**: `approval_ttl` enforced inside the decision compare-and-set;
  HTTP 410 `APPROVAL_EXPIRED`; `ART_APPROVAL_TTL_SECONDS` (production default 24 h).
- **Tamper-evident audit**: hash chain, `scripts/verify_audit_log.py`, SIEM reconciliation.
- **Checkpoint deserialization allow-list** for LangGraph state.
- **Lab demo**: `python -m art_sim.demo` — one command, synthetic estate, before/after graph,
  explained risk score, human approval, audit evidence, reproducible report ([docs/demo.md](docs/demo.md)).
- **Clean-clone reproduction**: `scripts/reproduce.sh` + evidence bundle ([docs/reproducibility.md](docs/reproducibility.md)).
- **Integration verification** against real PostgreSQL, Redis, OpenTelemetry Collector and Vault,
  and the AWS Secrets Manager API via `moto` ([docs/integrations.md](docs/integrations.md)).
- Tests: approval controls, organization/role matrix, audit integrity, lifecycle integrity on
  SQLite and PostgreSQL, mid-graph checkpoint recovery.
- `Dockerfile`: optional BuildKit `ca_bundle` secret (TLS-intercepting proxies) and
  `OS_UPGRADE` build arg (default `true`; `false` yields a non-releasable local image).
- `requirements.lock` regenerated and now complete (it was missing alembic, SQLAlchemy, boto3,
  hvac, moto and respx).

### Security
- Container image now closes every fixable OS CVE: the runtime stage runs `apt-get upgrade`
  (66 High → 0 fixable High/Critical), and `.grype.yaml` enforces an `only-fixed`, fail-on
  `high` policy with one documented CPython pre-release disposition.
- Runtime dependencies are hash-pinned; the image is built with `--require-hashes`, so the
  build fails if any dependency is tampered with or a hash is missing.
- Added CodeQL (`security-extended`) analysis for Python and TypeScript, Dependabot weekly
  updates (pip, npm, GitHub Actions, Docker), and a pre-commit config (ruff, bandit,
  gitleaks, private-key detection).
- Added Bandit static analysis to CI and a strict Content-Security-Policy injected into the
  production frontend build.
- Added `SECURITY.md` (disclosure policy and secret handling).

### Added
- `docker-compose.yml` for a one-command hardened local stack (optional Neo4j under the
  `shadow` profile) and a `Makefile` task runner.
- MIT `LICENSE` with a non-binding defensive-use notice.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, this changelog, issue/PR templates, `CODEOWNERS`, and `.editorconfig`.
- **Real production secret adapters**: `AwsSecretsManagerProvider` (AWS Secrets Manager)
  and `VaultSecretProvider` (HashiCorp Vault KV v2), implementing `ExternalSecretProvider`
  alongside the existing `MountedSecretsProvider`.
- **Direct SIEM audit forwarding**: `SiemForwardAuditSink` composes durable local capture
  with best-effort, retried HTTP delivery to a SIEM/HEC endpoint, never losing an event to
  a SIEM outage.
- **Versioned PostgreSQL migrations**: Alembic (`migrations/`, `scripts/run_migrations.py`,
  a Helm pre-install/pre-upgrade hook `Job`), replacing ad hoc `CREATE TABLE IF NOT EXISTS`
  as the production schema-evolution path. `PostgresOperationalStore.initialize()` remains
  as a dev/bootstrap convenience.
- **Automated data-retention purge job**: `art_sim.retention.job.RetentionJob`, PostgreSQL
  purge methods (`purge_expired_runs`/`_checkpoints`/`_results`) and
  `RedisStreamsBrokerTransport.purge_dead_letter`, enforcing the `ART_*_RETENTION_DAYS`
  policy table in `docs/data-retention.md` for the first time, with dry-run support, an
  audit event per run, and a Helm `CronJob` (disabled by default).
- **Executable disaster-recovery drill**: `scripts/backup_restore_drill.sh` runs the
  documented backup → failure → restore → verify procedure against disposable PostgreSQL
  containers it creates itself, scheduled weekly in `.github/workflows/dr-drill.yml`.
- **TLS edge configuration**: a Helm `Ingress` template (cert-manager annotations) and a
  Caddy `docker-compose` overlay for non-Kubernetes deployments, documented in
  `docs/tls-edge.md`.
- **Independent container-provenance verification**: the container image is now pushed to
  GHCR by digest and attested (`attest-container`); a separate `verify-container-provenance`
  CI job and `scripts/verify_image_provenance.py` re-verify that attestation independently
  (a deploy pipeline or operator can run the same script against the digest it is about to
  promote) — see `docs/supply-chain.md`.

### Changed
- README elevated with badges, a 60-second quickstart, a verified-operational section, and
  updated supply-chain / production-readiness status (NOT READY only pending external infra).

### Verified
- 184 backend tests, 20 frontend tests, Ruff, strict Mypy (100 files), Bandit (0 findings),
  pip-audit, npm audit, Gitleaks (full history, 0 leaks), and the Grype image gate all pass.
- End-to-end Shadow pipeline validated against a live Neo4j instance: seed → recon → MITRE
  planning → simulation → human approval → verification, reducing simulated risk 51.0 → 0.0.

### Confirmed (hosted)
- GitHub Actions `ci`, `codeql`, and `scorecard` workflows pass on `main` (hosted runners),
  including container build, Grype `high` gate, SBOMs, and build-provenance attestation.

### Security (defense-in-depth)
- Added adversarial test batteries for the prompt-injection sanitizer (control-char
  stripping, instruction-marker redaction, length bounding) and credential redaction
  (bearer/JWT/password/token shapes fully redacted, no partial leakage).
- Hardened the Cypher validator: `CREATE`/`REMOVE` forbidden outright and write clauses
  (`MERGE`/`SET`) rejected under read intent, so a read can never mutate the graph even if
  the forbidden list is relaxed. Added 33 adversarial tests (all real production queries
  pass; 24+ injection attempts fail closed). Backend suite now 184 tests.

### Added (production adapter)
- First concrete production adapter: `RedisRateLimiter` for the distributed rate-limit port
  (`pip install .[redis]`). Atomic sliding-window log via a single Lua script, so the limit
  holds across replicas. 8 tests (limit enforcement, independent keys/policies, window
  rollover, concurrency = exactly N allowed, backend-error mapping) using fakeredis[lua].
  Backend suite now 192 tests.

### Added (simulation coverage)
- Enriched the scenario catalog from 5 to 8 Shadow scenarios and completed the MITRE
  technique mapping for every relationship type: CONTAINER_ESCAPE→T1611 (Escape to Host),
  CREDENTIAL_ACCESS→T1552 (Unsecured Credentials), IAM_ASSUME_ROLE→T1548 (Abuse Elevation
  Control), ACCESS→T1210 (Exploitation of Remote Services). New scenarios: container
  breakout, IAM privilege chain, credential harvest. Verified end-to-end (succeeded +
  verified) through the live API. Backend suite now 200 tests.

### Security (robustness: fuzzing + mutation)
- Added dependency-free randomized fuzzing (3,000 iterations each) for the Cypher validator,
  prompt-injection sanitizer, and credential redaction, asserting their invariants. The fuzz
  suite found and fixed a sanitizer non-idempotency at the truncation boundary (trailing
  whitespace could reach the planner). Backend suite now 210 tests.
- Added on-demand mutation-testing config (`make mutation`, mutmut; Linux/WSL) targeting the
  security-critical modules so surviving mutants reveal weak test assertions.

### Added (production adapter)
- Second concrete production adapter: `OtlpTelemetrySink` for the external telemetry port
  (`pip install .[telemetry]`). Maps the bounded metric vocabulary to OpenTelemetry
  counters/histograms and agent executions to correlated spans; high-cardinality ids go on
  spans, not metric labels. 7 tests via in-memory OTel exporters (counter sum, histogram
  sum/count, span attributes, error status, health flush, backend-error mapping).
  production-readiness: 'Concrete telemetry exporter' now IMPLEMENTED. Backend suite now 217.

### Added (production adapters)
- `JsonlDurableSecurityAuditSink`: durable append-only (fsync) security-audit sink satisfying
  `DurableSecurityAuditSink`; survives restarts; stores the same redacted typed events.
- `MountedSecretsProvider`: external secret provider reading Docker/K8s mounted secrets, with
  strict name validation and base-dir containment (path-traversal-safe), satisfying
  `ExternalSecretProvider`. Both stdlib-only, opt-in, fully tested.
- production-readiness: 'Concrete durable audit adapter' and 'Concrete managed-secret adapter'
  now IMPLEMENTED. Backend suite now 239 tests.
- Made the Redis adapter's EVAL typing stub-version-agnostic (await via Any) so mypy passes
  under both the locked redis and newer local stubs.

### Added (production adapter)
- `RedisStreamsBrokerTransport` + `RedisStreamsJobConsumer`/`RedisStreamsJobDelivery`:
  real Redis Streams broker satisfying `BrokerTransport` and the consumer/delivery contract.
  Publish idempotency via SET NX dedup; at-least-once with explicit XACK; visibility
  redelivery of stalled jobs via XAUTOCLAIM; dead-letter stream for poison jobs. Paired with
  the existing BrokerSimulationDispatcher (DISTRIBUTED). 10 tests via fakeredis (idempotency,
  receive/decode, ack, timeout reclaim with attempt increment, DLQ, cancellation, pause).
- production-readiness: 'Concrete broker adapter' now IMPLEMENTED. Backend suite now 249 tests.
  Only the PostgreSQL operational store remains among the major NOT-IMPLEMENTED adapters.

### Added (production adapter — capstone)
- `PostgresOperationalStore`: server-grade asyncpg implementation of the full OperationalStore
  contract (runs, idempotent creation, approval CAS, worker leases/fencing, checkpoints with
  integrity, immutable results/reviews, append-only audit). Mirrors the SQLite store's logic;
  uses `SELECT ... FOR UPDATE` row locks (the Postgres equivalent of BEGIN IMMEDIATE) and
  timestamptz comparisons. Opt-in via `pip install .[postgres]`.
- 9 integration tests against a REAL PostgreSQL (dev container / CI service) covering
  single-owner acquisition, fencing-token increment on lease expiry, stale-worker rejection,
  approval CAS idempotency, idempotent creation, cancellation, and health. CI now runs a
  postgres:16 service so these execute (not skip). Backend suite now 258 tests.
- Every application-side production adapter now has a concrete implementation; production
  readiness is gated only by connecting them to live vendor services (deployment-owned).

### Added (deployment + production composition — final mile)
- Production composition root `art_sim.api.compose.build_production_app()` wires all six real
  adapters (OIDC, PostgreSQL store, Redis Streams broker, Redis rate limiter, OTLP telemetry,
  durable audit, mounted secrets) from env and passes create_production_app's fail-closed
  capability contract; `art_sim.api.serve` is the production ASGI entrypoint.
- Helm chart (deploy/helm/art-sim): hardened Deployment (non-root, read-only rootfs, drop ALL
  caps, seccomp), probes, HPA, PodDisruptionBudget, NetworkPolicy, projected secret volume.
  Validated with helm lint + helm template + rendered-manifest hardening assertions.
- docker-compose.prod.yml + OTLP collector config: full production-like stack.
- Verified END-TO-END: the production container starts and /readiness reports database,
  broker, secret_provider, rate_limiter, audit and telemetry all `ok` (6/7 adapters live);
  only identity_provider needs a real OIDC tenant. Grype gate still passes with the added
  adapter dependencies (runtime lock now ships them, hash-pinned). Backend suite now 261 tests.
- production-readiness: 'Deployment automation' now IMPLEMENTED.
