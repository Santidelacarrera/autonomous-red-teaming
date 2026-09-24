# Phase 11 completion record

## Implemented

- Thin API-to-dispatcher hand-off after durable, idempotent run creation.
- Process-local development dispatcher with startup recovery and clean shutdown.
- SQLite compare-and-set execution claims, expiring leases, bounded attempts, and
  terminal-state protection.
- Official async SQLite LangGraph checkpoints for attack planning and remediation HITL.
- Restart-safe approval and rejection using durable CAS plus HMAC-bound evidence.
- Deterministic risk, attack-path, blast-radius, remediation, verification, and report
  persistence with atomic success commit.
- Real result API reads and frontend polling for all active lifecycle states.
- Safe worker audit events, trace correlation, counters, and duration metrics.
- Unit and API integration coverage for success, HITL restart, rejection, duplicate
  delivery, competing workers, unknown scenarios, checkpoint failures, Shadow
  immutability, and secret-free audit.

## External production dependencies

- A distributed dispatcher/broker and separately deployed worker runtime.
- A server-grade operational/checkpoint store implementing the existing ownership and
  persistence contracts.
- A managed secret provider supplying stable approval signing material.
- Production observability, deployment, retention, and incident-response integrations.

Production composition requires an injected dispatcher with `DISTRIBUTED` scope and
fails closed without one. It never silently substitutes the process-local queue.

## Deliberately not implemented

- Real exploit, credential-access, cloud, Kubernetes, or infrastructure execution.
- Automatic application of Terraform, OpenTofu, IAM, OPA, or Gatekeeper changes.
- Vendor-specific queue, database, secret-manager, SIEM, or deployment adapters.
- A public cancellation endpoint and cooperative cancellation while a stage is running.
- Unbounded automatic retry or result regeneration after terminal completion.

The Phase 11 orchestration surface is complete for the repository's Shadow-only local
baseline. Overall production readiness remains **READY WITH EXTERNAL DEPENDENCY**, not a
claim that the repository alone is a deployable multi-node production system.
