# Production deployment contract

No deployment is executed by this repository. The target topology is:

```text
Client -> TLS/API Gateway/WAF -> FastAPI replicas -> Dispatcher -> Broker
       -> Worker replicas -> Server Operational Store
       -> Secret Manager / OIDC / Distributed Rate Limiter / SIEM / Telemetry
```

## Current implementation status

This is an operator contract, not a deployable production bundle. The repository does not
contain concrete broker, PostgreSQL, managed-secret, distributed-limiter, SIEM or telemetry
adapters, database migrations, or a production composition entry point that constructs
them. Creating a Compose/Kubernetes manifest around development adapters would violate the
production capability checks and is intentionally not done.

Before a reproducible deployment can be produced, operators must select one provider per
boundary, implement and integration-test the adapter, then bind it through
`create_production_app`. A manifest is accepted only when it references secrets by managed
identifier, pins the application image by digest, configures all readiness probes, and
contains no development identity, SQLite, process queue or in-memory limiter.

## Procedure

1. **Prerequisites:** select supported Python/container runtime, regions, DNS, certificate,
   network policies, workload identities and a controlled Shadow-data source.
2. **Secrets:** create separate approval HMAC, database, broker and optional OIDC client
   values in a managed provider; grant read-only workload access and record rotation.
3. **Database:** deploy PostgreSQL/equivalent, implement/certify `ServerOperationalStore`,
   enable TLS, backups, row locking/CAS and least privilege.
4. **Broker:** implement one `BrokerTransport`/consumer adapter with ack/nack, visibility,
   DLQ, backpressure, bounded retry and workload authentication.
5. **Identity:** configure a production OIDC resource server, audience, HTTPS JWKS,
   asymmetric algorithms, role claims and trusted MFA contract.
6. **Telemetry:** inject an external OTLP/Prometheus-compatible sink with redaction,
   bounded cardinality, export timeout and alerts.
7. **Audit:** inject a durable append-only SIEM/event-stream sink with access controls,
   clock synchronization and configured retention/archive.
8. **Rate limiting:** supply atomic distributed enforcement and edge/WAF limits for IP,
   user, create, approval, cancellation and admin endpoints.
9. **API gateway:** terminate TLS, configure WAF/request/connection/time limits, preserve
   request IDs, and trust only the configured proxy hop count.
10. **Workers:** deploy independently with no cloud/Kubernetes mutation credentials;
    configure graceful drain, lease/heartbeat, broker visibility and concurrency.
11. **Migrations:** back up first, apply reviewed forward migrations once, then verify the
    schema and adapter capability before replicas become ready.
12. **Health:** use `/health` only for process liveness and `/readiness` for database,
    broker, secrets, identity, limiter, audit and telemetry traffic gating.
13. **Rollback:** stop new dispatch, drain workers, restore a compatible application
    version; restore schema/data only from a verified backup when forward compatibility
    is impossible. Never edit lifecycle rows manually.
14. **Graceful shutdown:** remove readiness, stop accepting work, drain API/broker
    publishes, persist checkpoints, release leases, flush audit/telemetry and close pools.
15. **Backup:** include database/checkpoints/results and external audit configuration;
    exclude secret values from application backups and test restores routinely.
16. **Disaster recovery:** follow [disaster recovery](disaster-recovery.md), with measured
    operator-defined RPO/RTO before production approval.

## Release and rollback gate

Promotion requires a successful hosted workflow tied to the candidate commit, retained
source/image SBOMs, passing dependency and image scans, a verified GitHub artifact
attestation, reviewed migrations, and an isolated restore rehearsal. Rollback must use a
previously attested image digest whose schema compatibility was established before the
migration. No CI workflow in this repository deploys or rolls back production resources.

## Container and edge

Build with `docker build -t art-sim:<immutable-version> .`. Run as UID/GID 10001 with a
read-only root filesystem, `/tmp` tmpfs and only the required data mount. Never bake
`.env` or credentials. The shipped `art_sim.api.main` is development-only and deliberately
rejects `ART_ENV=production`; a deployment package must construct `create_production_app`
with certified adapters.
