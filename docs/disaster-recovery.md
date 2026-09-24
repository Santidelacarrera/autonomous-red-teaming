# Disaster recovery

RPO and RTO are operator-defined targets, not repository guarantees. Establish them only
after measuring the selected database, broker, audit and artifact backends.

## Backup scope

- server operational database: runs, ownership/fencing, decisions, checkpoints, results,
  schema history and operational audit;
- broker topology/configuration and provider-native durable queue/DLQ backups where
  supported;
- immutable security audit/SIEM archive and retention configuration;
- non-secret deployment configuration, image digest, SBOM and artifact hashes;
- secret references and recovery policy, but never secret values in application backups.

## Controlled `backup -> failure -> restore -> resume`

1. Stop new dispatch and drain workers in a non-production controlled environment.
2. Record the latest run IDs, fencing tokens, schema version and artifact hashes.
3. Take provider-consistent database/audit backups and snapshot broker state if supported.
4. Inject a controlled database/process failure; do not alter external infrastructure.
5. Restore into an isolated recovery environment with separate identities/networking.
6. Validate migrations, checkpoint schema/hash, terminal artifacts, audit sequence and
   broker deduplication state.
7. Start one worker, allow expired leases to be reacquired with higher fencing tokens,
   and verify stale writes are rejected.
8. Resume `RUNNING`, `WAITING_APPROVAL` and `RESUMING` runs only when their checkpoint,
   workflow version, decision and secret-verification material are valid.
9. Run the Shadow E2E and compare results/audit evidence; then authorize normal scale-out.

## Failure-specific rules

| Failure | Detection | Failover/recovery | Verification and rollback boundary |
| --- | --- | --- | --- |
| Broker outage/replay | readiness, publish/consume failure metrics, DLQ alerts | stop dispatch, retain durable runs, recover provider, reconcile stable message IDs before consumers resume | prove no duplicate terminal result; roll back broker/config only through provider procedure |
| Database outage/corruption | readiness, transaction and fencing failures | stop readiness and dispatch; restore a verified provider backup into isolation | validate schema, leases, checkpoints and artifact hashes; never repair lifecycle rows ad hoc |
| Worker crash/stale worker | heartbeat/lease expiry and fencing rejection | wait for lease expiry; reacquire with a higher fencing token | prove one owner and one terminal result; stale publication must remain rejected |
| API replica failure | liveness/readiness and gateway target health | remove failed replica and route only to ready instances | verify idempotency and active requests; application rollback uses an attested compatible digest |
| Secret Manager outage/rotation | startup/readiness failure and provider health | fail closed; recover through provider-native replication/rotation | retrieve required names without logging values; never recover secrets from logs or jobs |
| OIDC/JWKS outage | identity readiness and bounded JWKS refresh failure | deny new authentication; use provider recovery, never development auth | verify issuer/audience/key rotation/MFA with non-production identities before reopening |
| Durable audit outage | audit health and append failure | stop sensitive operations until durable evidence is restored or reconciled | validate ordering, retention and redaction; do not silently downgrade to memory |
| Telemetry outage | exporter health and delivery-failure metric | keep safety controls authoritative; recover exporter/collector with bounded buffering | confirm correlation and redaction; telemetry loss does not authorize operations |
| Missing/corrupt checkpoint | checksum/version/load failure | do not resume; preserve evidence and fail the run safely | only a valid compatible checkpoint may resume; no manual payload editing |
| Result-store failure | atomic publication failure | do not mark success; retry only classified transient writes | verify one immutable result or none |
| Region failure | external health/routing and provider replication signals | operator-selected regional failover after fencing/consistency assessment | not validated; requires real multi-region topology and rollback drill |

SQLite backup/WAL recovery is valid only for local single-node development and is not a
production disaster-recovery design.

No RPO, RTO, regional failover or provider backup guarantee is claimed until it has been
defined and measured in the selected external infrastructure.
