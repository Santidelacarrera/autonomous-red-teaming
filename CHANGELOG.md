# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
