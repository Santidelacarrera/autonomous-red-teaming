# Simulation result persistence

A successful worker produces one immutable `SimulationArtifacts` document containing:

- graph and workflow versions plus `run_id`, scenario, generation time, and `trace_id`;
- bounded attack paths and deterministic risk assessment;
- blast-radius analysis;
- normalized remediation candidates and review-only policy artifacts;
- optional approval evidence and simulated verification;
- the canonical Markdown report.

`SqliteOperationalStore.complete_execution()` inserts the result and changes the run to
`SUCCEEDED` in the same transaction. This prevents a successful lifecycle state without
its result. The result row is keyed by `run_id` and cannot be overwritten; terminal runs
cannot execute again.

Rejected and failed runs do not receive successful result documents. Their run records
contain only lifecycle metadata and safe error codes. Operational events remain
append-only and separate from the result payload.

## API availability

The following endpoints read the persisted result and never regenerate or fabricate
security evidence:

```text
GET /api/v1/simulations/{run_id}/risk
GET /api/v1/simulations/{run_id}/attack-paths
GET /api/v1/simulations/{run_id}/blast-radius
GET /api/v1/simulations/{run_id}/remediations
GET /api/v1/simulations/{run_id}/verification
GET /api/v1/simulations/{run_id}/report
```

They return `409 RESULT_NOT_AVAILABLE` unless the run is `SUCCEEDED` and its immutable
result exists. Authentication and the endpoint-specific read permission still apply.
The report endpoint returns its explicit format and persisted Markdown content.

SQLite is a development/single-node implementation. Multi-replica production requires
a server-database repository that preserves the same transactional uniqueness,
compare-and-set, lease, immutable-result, and audit contracts.
