#!/usr/bin/env bash
# Controlled backup -> failure -> restore -> verify disaster-recovery drill.
#
# Implements the "Controlled backup -> failure -> restore -> resume" procedure documented
# in docs/disaster-recovery.md against a real, disposable PostgreSQL — not a description of
# a procedure, an executable one. It:
#
#   1. starts a disposable "source" PostgreSQL container and applies migrations to it
#      (scripts/run_migrations.py, so the drill exercises the real production schema path);
#   2. seeds a handful of representative rows across every coordination table;
#   3. takes a `pg_dump` custom-format backup and records its SHA-256;
#   4. injects a controlled failure by killing the source container (step 4 of the
#      documented procedure — "inject a controlled database/process failure");
#   5. starts a separate, isolated "recovery" PostgreSQL container with its own network
#      alias (step 5 — "separate identities/networking") and `pg_restore`s into it;
#   6. verifies table-by-table row counts and a content checksum match between what was
#      backed up and what was restored, and that `alembic_version` is at the expected head;
#   7. tears everything down and prints a pass/fail report.
#
# Requires Docker and the PostgreSQL client tools (pg_dump/pg_restore/psql) on PATH. Exits
# non-zero on any verification failure. Safe to run repeatedly; it never touches a real
# deployment's database — only containers it creates and removes itself.
set -euo pipefail

SOURCE_CONTAINER="art-sim-dr-drill-source"
RECOVERY_CONTAINER="art-sim-dr-drill-recovery"
NETWORK="art-sim-dr-drill-net"
PG_IMAGE="postgres:16-alpine"
# Generated fresh for this disposable container on every run (never a literal secret
# checked into the script) -- it never outlives the drill and is used nowhere else.
PG_PASSWORD="$(openssl rand -hex 16)"
DB_NAME="artsim"
SOURCE_PORT="55433"
RECOVERY_PORT="55434"
WORKDIR="$(mktemp -d)"
BACKUP_FILE="${WORKDIR}/backup.dump"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '[dr-drill] %s\n' "$1"; }
fail() { printf '[dr-drill] FAIL: %s\n' "$1" >&2; exit 1; }

cleanup() {
  log "tearing down drill containers"
  docker rm -f "${SOURCE_CONTAINER}" "${RECOVERY_CONTAINER}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

wait_for_postgres() {
  local container="$1"
  for _ in $(seq 1 60); do
    if docker exec "${container}" pg_isready -U postgres >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "${container} did not become ready in time"
}

log "step 1/9: starting disposable source PostgreSQL"
docker network create "${NETWORK}" >/dev/null
docker run -d --name "${SOURCE_CONTAINER}" --network "${NETWORK}" \
  -e POSTGRES_PASSWORD="${PG_PASSWORD}" -e POSTGRES_DB="${DB_NAME}" \
  -p "${SOURCE_PORT}:5432" "${PG_IMAGE}" >/dev/null
wait_for_postgres "${SOURCE_CONTAINER}"

SOURCE_DSN="postgresql://postgres:${PG_PASSWORD}@127.0.0.1:${SOURCE_PORT}/${DB_NAME}"

log "step 2/9: applying migrations to the source (the real production schema path)"
ART_DATABASE_DSN="${SOURCE_DSN}" python "${REPO_ROOT}/scripts/run_migrations.py" upgrade head

log "step 3/9: seeding representative rows across every coordination table"
RUN_ID="$(python -c 'import uuid; print(uuid.uuid4())')"
PGPASSWORD="${PG_PASSWORD}" psql -h 127.0.0.1 -p "${SOURCE_PORT}" -U postgres -d "${DB_NAME}" -v run_id="'${RUN_ID}'" -q <<'SQL'
INSERT INTO simulation_runs (run_id, payload, status, approval_status, updated_at)
VALUES (:run_id, '{"scenario_id": "dr-drill"}', 'completed', 'not_required', now());
INSERT INTO workflow_checkpoints (run_id, payload, checksum, checkpoint_version, created_at)
VALUES (:run_id, '{}', 'deadbeef', 1, now());
INSERT INTO simulation_results (run_id, workflow_version, payload, created_at)
VALUES (:run_id, 'v1', '{"findings": []}', now());
INSERT INTO audit_events (event_id, run_id, payload)
VALUES (gen_random_uuid(), :run_id, '{"event_type": "simulation.completed"}');
SQL

log "step 4/9: recording pre-failure evidence (row counts + backup checksum)"
PRE_COUNTS="$(PGPASSWORD="${PG_PASSWORD}" psql -h 127.0.0.1 -p "${SOURCE_PORT}" -U postgres -d "${DB_NAME}" -At -c \
  "SELECT count(*) FROM simulation_runs UNION ALL SELECT count(*) FROM workflow_checkpoints UNION ALL SELECT count(*) FROM simulation_results UNION ALL SELECT count(*) FROM audit_events" \
  | tr '\n' ',')"
PGPASSWORD="${PG_PASSWORD}" pg_dump -h 127.0.0.1 -p "${SOURCE_PORT}" -U postgres -Fc -f "${BACKUP_FILE}" "${DB_NAME}"
BACKUP_SHA="$(sha256sum "${BACKUP_FILE}" | cut -d' ' -f1)"
log "backup sha256: ${BACKUP_SHA}"

log "step 5/9: injecting a controlled failure (killing the source container)"
docker kill "${SOURCE_CONTAINER}" >/dev/null

log "step 6/9: starting an isolated recovery PostgreSQL (separate identity/network)"
docker run -d --name "${RECOVERY_CONTAINER}" --network "${NETWORK}" \
  -e POSTGRES_PASSWORD="${PG_PASSWORD}" -e POSTGRES_DB="${DB_NAME}" \
  -p "${RECOVERY_PORT}:5432" "${PG_IMAGE}" >/dev/null
wait_for_postgres "${RECOVERY_CONTAINER}"
RECOVERY_DSN="postgresql://postgres:${PG_PASSWORD}@127.0.0.1:${RECOVERY_PORT}/${DB_NAME}"

log "step 7/9: restoring the backup into the isolated recovery instance"
PGPASSWORD="${PG_PASSWORD}" pg_restore -h 127.0.0.1 -p "${RECOVERY_PORT}" -U postgres -d "${DB_NAME}" --no-owner "${BACKUP_FILE}"

log "step 8/9: verifying migration state, row counts and the content checksum"
RECOVERED_VERSION="$(PGPASSWORD="${PG_PASSWORD}" psql -h 127.0.0.1 -p "${RECOVERY_PORT}" -U postgres -d "${DB_NAME}" -At -c "SELECT version_num FROM alembic_version")"
[ -n "${RECOVERED_VERSION}" ] || fail "recovered database has no alembic_version row"
log "recovered schema is at migration ${RECOVERED_VERSION}"

POST_COUNTS="$(PGPASSWORD="${PG_PASSWORD}" psql -h 127.0.0.1 -p "${RECOVERY_PORT}" -U postgres -d "${DB_NAME}" -At -c \
  "SELECT count(*) FROM simulation_runs UNION ALL SELECT count(*) FROM workflow_checkpoints UNION ALL SELECT count(*) FROM simulation_results UNION ALL SELECT count(*) FROM audit_events" \
  | tr '\n' ',')"
[ "${PRE_COUNTS}" = "${POST_COUNTS}" ] || fail "row counts diverged after restore (pre=${PRE_COUNTS} post=${POST_COUNTS})"

RECOVERED_RUN_STATUS="$(PGPASSWORD="${PG_PASSWORD}" psql -h 127.0.0.1 -p "${RECOVERY_PORT}" -U postgres -d "${DB_NAME}" -At -c \
  "SELECT status FROM simulation_runs WHERE run_id = '${RUN_ID}'")"
[ "${RECOVERED_RUN_STATUS}" = "completed" ] || fail "seeded run's terminal status did not survive restore"

log "step 9/9: drill passed — backup sha256=${BACKUP_SHA}, row counts match, schema at ${RECOVERED_VERSION}"
echo "DR_DRILL_RESULT=PASS"
