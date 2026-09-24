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

Deletion jobs and archive backends are external and not implemented. A production adapter
must support auditable, idempotent deletion, legal-hold override, clock consistency and
failure reporting without including credentials or raw sensitive payloads.
