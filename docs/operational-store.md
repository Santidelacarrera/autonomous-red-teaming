# Operational store contract

`OperationalStore` is an asynchronous provider-neutral port. It owns run creation,
idempotency, lifecycle CAS, approvals, cancellation, leases, fencing, audit, and immutable
results. Application services and workers do not issue SQL directly.

## Capabilities

| Capability | Meaning |
| --- | --- |
| `SINGLE_NODE` | Development or one-node coordination only. |
| `SERVER_GRADE` | Shared transactional coordination for independent API and worker replicas. |

`SqliteOperationalStore` explicitly declares `SINGLE_NODE`. `ServerOperationalStore` is
the protocol for a future PostgreSQL or equivalent adapter; no fake PostgreSQL adapter is
provided. Production composition accepts only `SERVER_GRADE`.

## Required server transaction semantics

A conforming server adapter must provide:

- unique idempotency keys and run IDs;
- row-level or equivalent serialized claim CAS;
- database-clock lease expiry and monotonically increasing fencing tokens;
- conditional writes matching run, owner, token, and live lease;
- atomic result insert plus transition to `SUCCEEDED`;
- immutable result uniqueness by `run_id`;
- approval and cancellation CAS;
- append-only audit evidence;
- rollback on version, run, ownership, or artifact conflicts.

The current SQLite schema migration adds fencing generation while preserving prior lease
attempts. SQLite WAL is not represented as safe for multiple hosts or regions.
