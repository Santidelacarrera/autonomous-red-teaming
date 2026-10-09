# External integrations — verified vs. pending

Every integration is in exactly one state. Nothing is reported as connected unless a test or
drill actually reached the service, and each "verified" row says **what it was verified
against**, because "a fake passed" and "a real server passed" are different claims.

| State | Meaning |
|---|---|
| **VERIFIED (real)** | A real server of that kind (a container started by the test/script) was used. |
| **VERIFIED (emulated API)** | The genuine client SDK ran against an in-process emulator of the vendor API. Proves our adapter and SDK usage, not a live account. |
| **CONTRACT ONLY** | A typed port with fail-closed capability checks exists; no concrete adapter or no run. |
| **PENDING** | Needs an environment this repository does not provision. Listed with exactly how to verify it. |

Run everything below with `bash scripts/reproduce.sh --with-docker --require-services`
(see [reproducibility.md](reproducibility.md)).

## Verified

| Integration | Adapter | State | Evidence | Findings fixed while validating |
|---|---|---|---|---|
| **PostgreSQL** (persistent backend) | `PostgresOperationalStore` + Alembic migrations | **VERIFIED (real)** — PostgreSQL 16, local and as a CI service container | 9 store + 4 migration + 7 retention integration tests; the lifecycle-integrity suite (95 cases) runs on SQLite *and* PostgreSQL; production composition test; **disaster-recovery drill executed: backup → kill → isolated restore → verified (`DR_DRILL_RESULT=PASS`)** | Migration `0001` sent seven `CREATE TABLE` in one statement, which asyncpg rejects — the Helm migration Job would have **always failed**. `migrations/env.py` silenced every other logger in the process. The DR drill raced the image's init server. |
| **Redis** — job broker (Streams), distributed rate limiter, dead-letter purge | `RedisStreamsBrokerTransport`, `RedisRateLimiter` | **VERIFIED (real)** — Redis 7.0 | The same 41 tests run against `fakeredis` *and* a real server (`ART_REDIS_TEST_URL`), incl. the Lua sliding window, consumer groups, visibility redelivery, DLQ | — |
| **Message queue** (distributed jobs) | Redis Streams | **VERIFIED (real)** | as above. The architecture *does* need a queue (API and workers are separate processes) and this is it. | — |
| **OpenTelemetry → monitoring destination** | `OtlpTelemetrySink` (OTLP/HTTP) | **VERIFIED (real)** — OpenTelemetry Collector 0.110.0 started with the repo's own `deploy/otel-collector.yaml` | `test_otel_collector.py`: metrics **and** a span (with `run_id`) are found in the Collector's own log; readiness goes red when the Collector stops. `test_otlp_wire.py`: protobuf decoded off a local OTLP receiver. | **Readiness reported healthy with the collector down** (`force_flush` swallows export errors). Added a TCP/health-URL probe. |
| **Secrets — HashiCorp Vault** | `VaultSecretProvider` (KV v2) | **VERIFIED (real)** — Vault 1.15 dev server | `test_vault_real.py` (7): read, missing path, token without policy, bogus token, rotation via `reload`, **sealed ⇒ not ready**, unreachable ⇒ bounded retries then unavailable | — (error classification by class name was confirmed against real `hvac` exceptions) |
| **Secrets — AWS Secrets Manager** | `AwsSecretsManagerProvider` | **VERIFIED (emulated API)** — real `boto3` against `moto` | `test_aws_secrets_moto.py`: read, missing ⇒ fails closed, **approval HMAC key resolved from the secret manager and used to sign**, rotation invalidates old signatures, short key refused | — |
| **Secrets — mounted files** (Docker/K8s secrets) | `MountedSecretsProvider` | **VERIFIED (real)** — real files; container run with read-only root | integration tests + hardened container smoke test | — |
| **SIEM / verifiable event output** | `JsonlDurableSecurityAuditSink` (hash chain), `SiemForwardAuditSink` (HTTP, raw JSON or Splunk-HEC framing) | **VERIFIED (real)** against a local HTTP ingestion server over a real socket; the **chain** is independently verifiable | `test_siem_wire.py`: HEC format, auth header, 5xx retry, wrong credentials counted, outage never loses a durable event. `test_audit_integrity.py`: gaps, duplicates, edits, reorder, torn write, truncation, and **SIEM loss/duplication reconciliation**. `scripts/verify_audit_log.py` is the operator tool. | `close()` raised `CancelledError` on every graceful shutdown. |
| **Container build/run** | `Dockerfile` | **VERIFIED (real)** — image built and run read-only, no capabilities, `no-new-privileges`, UID 10001 | `reproduce.sh --with-docker`; health 200, anonymous 401, create 202, SIGTERM exit 0 | — (build support for TLS-intercepting proxies added; see reproducibility.md) |

## Pending — external dependencies not available here

Declared explicitly, with the check that would close each one.

| Dependency | Why it is not verified | How to verify it | Risk until then |
|---|---|---|---|
| **Live OIDC tenant** (Entra ID / Okta / Auth0 / Keycloak) | None provisioned. JWT/JWKS handling is verified with locally signed tokens and a mock JWKS transport only. | Point `ART_OIDC_ISSUER/AUDIENCE/JWKS_URL` at the tenant; mint tokens for an operator, viewer and admin in two organizations; confirm `roles`, **`org_id`** (or `ART_OIDC_ORGANIZATION_CLAIM`) and the MFA claim values the tenant actually emits. | **Highest.** Tenant isolation depends on the IdP issuing a trustworthy organization claim; a token without it is rejected, but a *wrongly populated* one is not detectable here. |
| **A production SIEM** (Splunk, Elastic, Sentinel, Chronicle…) | Only a local HTTP stand-in was used. | Forward to the real HEC/ingest endpoint; confirm field mapping, acknowledgements, retention, and run `verify_audit_log.py --siem-ids export.txt` against an export. | Delivery semantics (ack, indexing latency) unproven. The forwarder is **at-least-once and best-effort with a bounded queue**: loss is *detectable* (reconciliation), but there is **no automated backfill** of missing events yet — it is a manual step from the durable log. |
| **A real metrics/traces backend** (Prometheus, Tempo, Grafana, a vendor) | The Collector hop is verified; what is behind it is not. | Replace the `debug` exporter in `deploy/otel-collector.yaml`; build dashboards/alerts on `simulations_*`, `approval_*`, `authorization_denied_total`, `cross_organization_denied_total`, `approval_expired_total`. | No alerting or SLOs exist. |
| **AWS Secrets Manager (live account)** | Emulated only. | Run the same adapter with a real region and an IAM role limited to the named secrets. | IAM/KMS permission shape and throttling behavior unproven. |
| **Vault auth methods / HA** | Dev-mode Vault with a root token. | AppRole or Kubernetes auth; token renewal (the adapter does not renew); a sealed/standby failover drill. | Token lifecycle is the deployer's responsibility. |
| **Managed PostgreSQL** (RDS, Cloud SQL, Aurora) and a **connection pooler** | Verified on a plain PostgreSQL 16 container. | Run the integration suite and the DR drill against the managed instance with `sslmode=verify-full`; if PgBouncer is in the path use *session* pooling (asyncpg prepared statements). | TLS, failover, replica lag and pooler behavior unproven. **No load benchmark exists**, so no capacity claim is made. |
| **Redis topology** (Cluster, Sentinel, TLS, ACL, persistence) | Verified on a single Redis 7.0. | Run the Redis suites with `rediss://` and your topology. | Queue durability depends on the Redis persistence (AOF) configuration, which is an operations decision. |
| **Neo4j / AuraDB** (Shadow graph adapter) | Validated in an earlier audit (see the README) but **not re-run in this pass** (no credentials here). | `make seed && make e2e` against a Shadow database. | Treated as unverified for this evidence set. |
| **GitHub pull-request publication** (remediation PRs) | CONTRACT ONLY; no real publication. | Run `GitHubPullRequestService` against a sandbox repository. | The pipeline stops at a reviewed artifact by design. |
| **TLS edge / WAF, image scanning, provenance attestation** | Configuration only, or hosted-CI-only. | Deploy the Helm chart / overlay; hosted CI runs Grype, attestation and `verify-container-provenance`. | — |
| **Alternative brokers** (RabbitMQ, Kafka, SQS) | CONTRACT ONLY — only the `BrokerProvider` enum exists. | Implement the transport behind `BrokerTransport`. | Not needed today; Redis Streams covers the architecture. |
| **Multi-region** | NOT IMPLEMENTED. | — | — |

## Operational notes that came out of the verification

- **Rotating the approval HMAC secret invalidates the signature on any decision that was recorded
  but not yet finalized.** A worker holding the new key refuses to resume a decision signed with
  the old one (it fails closed; see `test_rotating_the_secret_invalidates_proofs…`). Rotate when
  no run is `RESUMING`, or re-review the affected runs.
- A telemetry outage now turns **readiness** red. Telemetry still never authorizes or blocks a
  security decision, but an orchestrator will stop routing to a replica whose collector is down;
  if that is undesirable, drop `ART_OTLP_ENDPOINT` health from your readiness policy explicitly
  rather than letting it lie.
