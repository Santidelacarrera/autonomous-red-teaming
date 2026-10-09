# Data retention boundary

Retention values are explicit deployment configuration; the repository does not infer a
jurisdiction, legal hold, privacy regime or compliance schedule.

| Data class | Configuration | Deletion/archive behavior |
| --- | --- | --- |
| Security audit | `ART_AUDIT_RETENTION_DAYS`, optional archive threshold | Durable sink must archive before deletion when configured; legal hold is provider-owned. |
| Telemetry | `ART_TELEMETRY_RETENTION_DAYS` | Backend TTL/delete; labels remain restricted to typed correlation. |
| Simulation runs | `ART_SIMULATION_RETENTION_DAYS` | Delete terminal run metadata only after dependent evidence policy allows. |
| Result artifacts | `ART_RESULT_RETENTION_DAYS` | Immutable during retention; archive/hash before provider-owned deletion. |
| Checkpoints | `ART_CHECKPOINT_RETENTION_DAYS` | Never delete while a run can resume or approval is pending. |
| Dead-letter jobs | `ART_DEAD_LETTER_RETENTION_DAYS` | Delete safe poison records after investigation; raw payload retention is forbidden here. |

Archive backends (SIEM archive storage, result-artifact cold storage) remain external and
not implemented here, consistent with the rest of this document. **Deletion is now
implemented** as `art_sim.retention.job.RetentionJob`, which applies the configured
`ART_*_RETENTION_DAYS` values above against:

- `PostgresOperationalStore.purge_expired_runs` — deletes terminal simulation runs (and, in
  the same transaction, every dependent row: checkpoints, results, reviews, leases,
  idempotency records, operational audit events) once `updated_at` is older than
  `ART_SIMULATION_RETENTION_DAYS`. A run that can still resume or has a pending approval is
  never selected (its status is not in `SimulationRunStateMachine.TERMINAL`).
- `PostgresOperationalStore.purge_expired_checkpoints` /
  `purge_expired_results` — narrower, independent windows
  (`ART_CHECKPOINT_RETENTION_DAYS` / `ART_RESULT_RETENTION_DAYS`) for the common case where
  a run record is kept longer than its checkpoint/result payloads should be; both still
  only ever touch a terminal run's rows.
- `RedisStreamsBrokerTransport.purge_dead_letter` — deletes dead-lettered jobs older than
  `ART_DEAD_LETTER_RETENTION_DAYS`; "safe poison records" means the Redis Streams DLQ entry
  (payload + failure reason), there is no separate raw-payload store to leave behind.

Every purge method is dry-run capable (`dry_run=True` reports the count it would delete
without deleting anything) and `RetentionJob.run()` writes one
`SecurityEventType.DATA_RETENTION_PURGED` audit event per execution — a job that silently
deletes historical data without leaving its own evidence of having run would defeat the
audit trail the rest of this system is built around.

**Not** covered by this job, and still genuinely external:

- the durable security-audit/SIEM archive (`ART_AUDIT_RETENTION_DAYS` /
  `ART_AUDIT_ARCHIVE_AFTER_DAYS`) — that retention is the SIEM/archive backend's own
  lifecycle policy, enforced by the vendor service `SiemForwardAuditSink` forwards to (or
  the log shipper tailing `JsonlDurableSecurityAuditSink`'s file), not by application code;
- telemetry (`ART_TELEMETRY_RETENTION_DAYS`) — backend TTL/delete, owned by the OTLP/
  Prometheus backend.

Running it: `make retention-job-dry-run` to report, `make retention-job` to execute, or as
the Helm `CronJob` in `deploy/helm/art-sim/templates/retention-cronjob.yaml` — **disabled by
default** (`retention.enabled: false`) until an operator confirms the configured windows
match the organization's actual retention policy. See `scripts/run_retention_job.py`.
