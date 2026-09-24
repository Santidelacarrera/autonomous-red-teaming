# Operations runbooks

## Startup

Validate `SecuritySettings` and `ProductionDependencySettings`, construct only certified
adapters, retrieve/validate the approval secret, initialize/migrate the store, then enable
readiness. A missing/short secret or unsuitable capability stops startup. A later external
outage returns readiness 503 without exposing endpoints, credentials or exception text.

## Shutdown

Remove the replica from readiness, stop accepting publishes, drain bounded in-flight
work, persist a safe checkpoint, stop heartbeats, release owned leases and close broker,
telemetry, audit, limiter, identity, secret and database clients. SIGTERM is the container
stop signal. Never force a terminal success during shutdown.

## Broker outage

Confirm `BROKER_UNAVAILABLE`, pause new simulation creation at the edge if needed, retain
durable `CREATED` runs, monitor retry/backoff and restore the adapter. Do not manually
republish without the stable message ID. Route exhausted poison deliveries to the real
DLQ and inspect only safe metadata.

## Database outage

Readiness must fail. Stop worker claims/publication, preserve broker messages and avoid
acknowledging work that was not durably committed. Restore database service, validate
schema and fencing monotonicity, then resume consumers gradually.

## Secret rotation/outage

On outage, fail startup/readiness closed and never fall back to `.env` in production.
For rotation, stage a new version, atomically reload all replicas, verify readiness and
approval behavior, then revoke the old version. Rotate immediately after suspected leak.

## Worker and approval recovery

For a crashed worker, wait for lease expiry; a new owner receives a higher fencing token.
For `WAITING_APPROVAL`, preserve checkpoint and HMAC material, allow exactly one decision,
then dispatch `RESUMING`. A missing/corrupt checkpoint fails safely; create a new run only
after evidence preservation and operator review.

## Dead-letter handling

Quarantine the message, record reason/run/message/attempt only, verify scenario and
workflow compatibility, correct the root cause, and create an authorized new logical
attempt. Never copy raw payloads or credentials into tickets/logs.

## Rollback and recovery

Stop dispatch, drain, back up current evidence, roll back to a schema-compatible image,
run readiness and Shadow smoke tests, then resume. Follow the controlled restore sequence
in [disaster recovery](disaster-recovery.md).
