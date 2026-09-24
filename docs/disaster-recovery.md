# Disaster recovery

## Objectives

RPO and RTO are deployment targets, not guarantees: define them per environment after
measuring backup cadence, restore time, database size, and operator procedures.

## Failure and recovery

| Failure | Detection | Recovery | Integrity verification |
| --- | --- | --- | --- |
| Worker stop during run | Liveness loss / stale run | Restart with same SQLite file and signing secret; load checkpoint | Checkpoint SHA-256 and Pydantic schema validation. |
| Waiting approval restart | Run remains `waiting_approval` | Resume coordinator using durable run and checkpoint | HMAC approval and transactional pending-state CAS. |
| SQLite corruption | Checkpoint checksum/schema error or SQLite error | Restore database and WAL-consistent backup to an isolated path | Validate schema migration and inspect append-only audit sequence. |
| Secret rotation | Approval proof validation failure | Keep old verifier material only through a controlled rotation window; then revoke | Pending approvals signed solely by revoked material are rejected. |
| Neo4j outage | Readiness probe / repository error | Keep run recoverable; do not mark success | Re-run Shadow read after dependency recovery. |

Back up the SQLite database using SQLite-consistent backup tooling, including WAL state,
and separately back up non-secret configuration. Never put approval secrets in backups or
audit events. Schema migrations are versioned in `schema_migrations`; upgrades are
forward-only in this baseline. Restore rollback means restoring a verified pre-upgrade
backup, not manually editing tables.
