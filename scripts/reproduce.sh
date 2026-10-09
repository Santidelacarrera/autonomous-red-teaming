#!/usr/bin/env bash
# Reproduce and verify the whole demonstration from a clean clone — one command, one verdict.
#
#   git clone <repo> && cd <repo> && bash scripts/reproduce.sh
#
# What it does (each step is recorded as PASS / FAIL / SKIP / DEGRADED in evidence/summary.json):
#   1. creates an isolated virtualenv and installs ONLY from the pinned requirements.lock
#   2. static checks: ruff, strict mypy, bandit, pip-audit
#   3. provides real PostgreSQL and Redis (reuses ART_PG_TEST_DSN / ART_REDIS_TEST_URL, else
#      starts throwaway Docker containers) so the integration suites really run
#   4. runs the full backend test suite -> evidence/junit.xml
#   5. frontend: lint, typecheck, tests, build (needs Node; skipped with --skip-frontend)
#   6. secret scan with Gitleaks (uses an installed binary, builds one with Go, or uses Docker)
#   7. runs the lab demo and checks its findings digest against the committed reference,
#      then verifies the hash-chained audit log
#   8. optionally builds and smoke-tests the container image (--with-docker)
#
# Exit status is 0 only if no required step FAILED. A step that ran with reduced coverage (for
# example the database was unavailable, so database tests were skipped) is DEGRADED, is shown
# loudly, and fails the run under --strict / --require-services.
#
# Options:
#   --out DIR            evidence directory (default: evidence)
#   --venv DIR           virtualenv location (default: .repro/venv)
#   --python BIN         interpreter to use (default: python3; needs >= 3.11, 3.12 recommended)
#   --require-services   fail if PostgreSQL/Redis were unavailable or their tests were skipped
#   --strict             treat every DEGRADED step as a failure
#   --skip-frontend      do not run the Node/npm steps
#   --skip-audit         do not run pip-audit (it needs network access)
#   --with-docker        also build and smoke-test the container image
#
# Environment (all optional): ART_PG_TEST_DSN, ART_REDIS_TEST_URL, ART_PG_IMAGE / ART_REDIS_IMAGE
# (e.g. mirror.gcr.io/library/redis:7-alpine when Docker Hub rate-limits you), ART_BUILD_CA_BUNDLE (CA file
# for a TLS-intercepting proxy, passed to `docker build` as a BuildKit secret), OS_UPGRADE
# (set false only when the Debian mirrors are unreachable; such an image is not releasable).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

EVIDENCE="evidence"
VENV=".repro/venv"
PYTHON_BIN="python3"
REQUIRE_SERVICES=0
STRICT=0
SKIP_FRONTEND=0
SKIP_AUDIT=0
WITH_DOCKER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) EVIDENCE="$2"; shift 2 ;;
    --venv) VENV="$2"; shift 2 ;;
    --python) PYTHON_BIN="$2"; shift 2 ;;
    --require-services) REQUIRE_SERVICES=1; shift ;;
    --strict) STRICT=1; shift ;;
    --skip-frontend) SKIP_FRONTEND=1; shift ;;
    --skip-audit) SKIP_AUDIT=1; shift ;;
    --with-docker) WITH_DOCKER=1; shift ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

rm -rf "${EVIDENCE}"
mkdir -p "${EVIDENCE}" ".repro/bin"
STEPS="${EVIDENCE}/steps.tsv"
: > "${STEPS}"
STARTED_CONTAINERS=()

log()  { printf '\033[1m[repro]\033[0m %s\n' "$*"; }
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "${STEPS}"; log "$1: $2${3:+ — $3}"; }

cleanup() {
  for name in "${STARTED_CONTAINERS[@]:-}"; do
    [ -n "${name}" ] && docker rm -f "${name}" >/dev/null 2>&1
  done
}
trap cleanup EXIT

free_port() { "${PYTHON_BIN}" -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"; }
docker_ok() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

# --- preflight -------------------------------------------------------------------------------
log "repository: ${REPO_ROOT} @ $(git rev-parse --short HEAD 2>/dev/null || echo 'no git')"
if ! "${PYTHON_BIN}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
  record "preflight" FAIL "need Python >= 3.11 (got: $(${PYTHON_BIN} --version 2>&1))"
  "${PYTHON_BIN}" scripts/evidence_summary.py final --dir "${EVIDENCE}" >/dev/null 2>&1 || true
  exit 1
fi
record "preflight" PASS "$(${PYTHON_BIN} --version 2>&1)"
if git rev-parse --git-dir >/dev/null 2>&1 && [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  log "note: the working tree has uncommitted changes; the bundle records this"
fi

# --- 1. environment --------------------------------------------------------------------------
log "creating virtualenv ${VENV} from requirements.lock"
if "${PYTHON_BIN}" -m venv "${VENV}" \
   && "${VENV}/bin/python" -m pip install -q --disable-pip-version-check -r requirements.lock \
   && "${VENV}/bin/python" -m pip install -q --disable-pip-version-check -e . --no-deps; then
  record "install (pinned lock)" PASS "$("${VENV}/bin/python" -m pip list --format=freeze 2>/dev/null | wc -l | tr -d ' ') packages"
else
  record "install (pinned lock)" FAIL "pip could not install requirements.lock (network? CA bundle? see docs/reproducibility.md)"
  "${PYTHON_BIN}" scripts/evidence_summary.py final --dir "${EVIDENCE}" || true
  exit 1
fi
PY="${VENV}/bin/python"
export PATH="${PWD}/${VENV}/bin:${PWD}/.repro/bin:${PATH}"

# --- 2. static checks ------------------------------------------------------------------------
run_step() { # name, logfile, command...
  local name="$1" logfile="$2"; shift 2
  if "$@" > "${EVIDENCE}/${logfile}" 2>&1; then record "${name}" PASS ""; else
    record "${name}" FAIL "see ${EVIDENCE}/${logfile}"; tail -n 15 "${EVIDENCE}/${logfile}" >&2
  fi
}
run_step "ruff" ruff.txt "${PY}" -m ruff check .
run_step "mypy --strict" mypy.txt "${PY}" -m mypy .
run_step "bandit" bandit.txt "${PY}" -m bandit -q -c pyproject.toml -r src
if [ "${SKIP_AUDIT}" = 1 ]; then
  record "pip-audit" SKIP "--skip-audit"
else
  # pip-audit is a scanner, not a dependency of the product, so it is deliberately not in the
  # lock: install the current release on demand (its job is to know today's advisories).
  "${PY}" -m pip install -q --disable-pip-version-check pip-audit > "${EVIDENCE}/pip-audit.txt" 2>&1
  if "${PY}" -m pip_audit -r requirements.lock --progress-spinner off >> "${EVIDENCE}/pip-audit.txt" 2>&1; then
    record "pip-audit" PASS "$(tail -n1 "${EVIDENCE}/pip-audit.txt")"
  else
    record "pip-audit" FAIL "see ${EVIDENCE}/pip-audit.txt (needs network access to PyPI/OSV)"
  fi
fi

# --- 3. real services ------------------------------------------------------------------------
PG_NOTE="" ; REDIS_NOTE=""
if [ -z "${ART_PG_TEST_DSN:-}" ]; then
  if docker_ok; then
    PORT="$(free_port)"; PG_PASS="$(${PY} -c 'import secrets; print(secrets.token_hex(12))')"
    NAME="art-sim-repro-pg-$$"
    if docker run -d --name "${NAME}" -e POSTGRES_PASSWORD="${PG_PASS}" -e POSTGRES_DB=artsim \
         -p "127.0.0.1:${PORT}:5432" "${ART_PG_IMAGE:-postgres:16-alpine}" >/dev/null 2>&1; then
      STARTED_CONTAINERS+=("${NAME}")
      for _ in $(seq 1 90); do
        banners="$(docker logs "${NAME}" 2>&1 | grep -c 'database system is ready to accept connections' || true)"
        [ "${banners}" -ge 2 ] && break; sleep 1
      done
      export ART_PG_TEST_DSN="postgresql://postgres:${PG_PASS}@127.0.0.1:${PORT}/artsim"
      PG_NOTE="started postgres:16-alpine on :${PORT}"
    else
      PG_NOTE="could not start a PostgreSQL container (image pull failed or rate-limited)"
    fi
  else
    PG_NOTE="no ART_PG_TEST_DSN and no usable Docker daemon"
  fi
else
  PG_NOTE="using ART_PG_TEST_DSN"
fi
if [ -z "${ART_REDIS_TEST_URL:-}" ]; then
  if docker_ok; then
    PORT="$(free_port)"; NAME="art-sim-repro-redis-$$"
    if docker run -d --name "${NAME}" -p "127.0.0.1:${PORT}:6379" "${ART_REDIS_IMAGE:-redis:7-alpine}" >/dev/null 2>&1; then
      STARTED_CONTAINERS+=("${NAME}"); sleep 2
      export ART_REDIS_TEST_URL="redis://127.0.0.1:${PORT}/15"
      REDIS_NOTE="started redis:7-alpine on :${PORT}"
    else
      REDIS_NOTE="could not start a Redis container"
    fi
  else
    REDIS_NOTE="no ART_REDIS_TEST_URL and no usable Docker daemon"
  fi
else
  REDIS_NOTE="using ART_REDIS_TEST_URL"
fi
if [ -n "${ART_PG_TEST_DSN:-}" ] && [ -n "${ART_REDIS_TEST_URL:-}" ]; then
  record "services (PostgreSQL + Redis)" PASS "${PG_NOTE}; ${REDIS_NOTE}"
elif [ "${REQUIRE_SERVICES}" = 1 ]; then
  record "services (PostgreSQL + Redis)" FAIL "${PG_NOTE}; ${REDIS_NOTE} (--require-services)"
else
  record "services (PostgreSQL + Redis)" DEGRADED "${PG_NOTE}; ${REDIS_NOTE} — dependent tests will be SKIPPED"
fi

# --- 4. test suite ---------------------------------------------------------------------------
log "running the backend test suite (this takes about a minute)"
"${PY}" -m pytest -q -p no:cacheprovider -rs --junitxml="${EVIDENCE}/junit.xml" \
  > "${EVIDENCE}/pytest.txt" 2>&1
PYTEST_STATUS=$?
tail -n 4 "${EVIDENCE}/pytest.txt"
SKIP_PATTERN=""
[ "${REQUIRE_SERVICES}" = 1 ] && SKIP_PATTERN='No PostgreSQL|ART_REDIS_TEST_URL|unreachable'
if [ -f "${EVIDENCE}/junit.xml" ]; then
  "${PY}" scripts/evidence_summary.py junit "${EVIDENCE}/junit.xml" ${SKIP_PATTERN:+--fail-on-skip "${SKIP_PATTERN}"} \
    > "${EVIDENCE}/junit-summary.md" 2>&1
  SUMMARY_STATUS=$?
else
  SUMMARY_STATUS=1
fi
TOTALS="$(sed -n '3p' "${EVIDENCE}/junit-summary.md" 2>/dev/null | tr -d '|' | xargs)"
if [ "${PYTEST_STATUS}" -ne 0 ] || [ "${SUMMARY_STATUS}" -ne 0 ]; then
  record "pytest" FAIL "${TOTALS:-no junit output} — see ${EVIDENCE}/pytest.txt"
else
  record "pytest" PASS "tests/passed/failed/skipped/time: ${TOTALS}"
fi

# --- 5. frontend -----------------------------------------------------------------------------
if [ "${SKIP_FRONTEND}" = 1 ]; then
  record "frontend (lint, types, tests, build)" SKIP "--skip-frontend"
elif ! command -v npm >/dev/null 2>&1; then
  record "frontend (lint, types, tests, build)" SKIP "Node/npm not installed"
else
  if ( cd frontend && npm ci --no-audit --no-fund && npm run lint && npm run typecheck && npm test -- --run && npm run build ) \
       > "${EVIDENCE}/frontend.txt" 2>&1; then
    record "frontend (lint, types, tests, build)" PASS "$(grep -E 'Tests +[0-9]+ passed' "${EVIDENCE}/frontend.txt" | tail -n1 | xargs)"
  else
    record "frontend (lint, types, tests, build)" FAIL "see ${EVIDENCE}/frontend.txt"
  fi
fi

# --- 6. secret scan --------------------------------------------------------------------------
GITLEAKS_VERSION="v8.18.4"
GITLEAKS=""
if command -v gitleaks >/dev/null 2>&1; then
  GITLEAKS="$(command -v gitleaks)"
elif command -v go >/dev/null 2>&1; then
  # GitHub Releases is blocked on some networks; the Go module proxy usually is not.
  log "building gitleaks ${GITLEAKS_VERSION} with Go (release download not required)"
  GOBIN="${PWD}/.repro/bin" go install "github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}" \
    > "${EVIDENCE}/gitleaks-build.txt" 2>&1 && GITLEAKS="${PWD}/.repro/bin/gitleaks"
fi
if [ -n "${GITLEAKS}" ] && git rev-parse --git-dir >/dev/null 2>&1; then
  if "${GITLEAKS}" detect --source . --no-banner --redact > "${EVIDENCE}/gitleaks.txt" 2>&1; then
    record "gitleaks (git history)" PASS "$(grep -E 'commits scanned' "${EVIDENCE}/gitleaks.txt" | sed 's/.*INF//' | xargs)"
  else
    record "gitleaks (git history)" FAIL "findings or error — see ${EVIDENCE}/gitleaks.txt"
  fi
elif docker_ok && git rev-parse --git-dir >/dev/null 2>&1 \
     && docker run --rm -v "${PWD}:/repo" "zricethezav/gitleaks:${GITLEAKS_VERSION}" detect --source /repo --no-banner --redact \
        > "${EVIDENCE}/gitleaks.txt" 2>&1; then
  record "gitleaks (git history)" PASS "via Docker image"
else
  record "gitleaks (git history)" DEGRADED "no gitleaks binary, Go toolchain or Docker image available; CI still runs the gate"
fi

# --- 7. demo + audit chain -------------------------------------------------------------------
if "${PY}" -m art_sim.demo --out "${EVIDENCE}/demo" --quiet > "${EVIDENCE}/demo.txt" 2>&1; then
  record "lab demo" PASS "$(grep -E 'Reproducibility' "${EVIDENCE}/demo.txt" | sed 's/^ *Reproducibility *: //')"
else
  record "lab demo" FAIL "see ${EVIDENCE}/demo.txt"
fi
if [ -f "${EVIDENCE}/demo/audit/security.jsonl" ]; then
  if "${PY}" scripts/verify_audit_log.py "${EVIDENCE}/demo/audit/security.jsonl" > "${EVIDENCE}/audit-verify.txt" 2>&1; then
    record "audit hash chain" PASS "$(head -n1 "${EVIDENCE}/audit-verify.txt" | cut -c1-80)"
  else
    record "audit hash chain" FAIL "see ${EVIDENCE}/audit-verify.txt"
  fi
fi

# --- 8. container image ----------------------------------------------------------------------
if [ "${WITH_DOCKER}" = 1 ]; then
  if ! docker_ok; then
    record "container image" SKIP "no usable Docker daemon (start dockerd, see docs/reproducibility.md)"
  else
    BUILD_ARGS=(--build-arg "OS_UPGRADE=${OS_UPGRADE:-true}")
    [ -n "${ART_BUILD_CA_BUNDLE:-}" ] && BUILD_ARGS+=(--secret "id=ca_bundle,src=${ART_BUILD_CA_BUNDLE}")
    if docker build "${BUILD_ARGS[@]}" -t art-sim:repro . > "${EVIDENCE}/docker-build.txt" 2>&1; then
      NAME="art-sim-repro-app-$$"; PORT="$(free_port)"
      docker run -d --name "${NAME}" --read-only --cap-drop ALL --security-opt no-new-privileges \
        --tmpfs /tmp --tmpfs /app/var:uid=10001,gid=10001 -e ART_SIM_OPERATIONAL_DB=/app/var/ops.sqlite3 \
        -p "127.0.0.1:${PORT}:8080" art-sim:repro >/dev/null 2>&1 && STARTED_CONTAINERS+=("${NAME}")
      sleep 6
      HEALTH="$(curl -s -m 5 "http://127.0.0.1:${PORT}/health" || true)"
      UNAUTH="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/v1/simulations" || true)"
      if echo "${HEALTH}" | grep -q '"status":"ok"' && [ "${UNAUTH}" = "401" ]; then
        if [ "${OS_UPGRADE:-true}" = "false" ]; then
          record "container image" DEGRADED "built and healthy (read-only, no caps, 401 when anonymous) but OS_UPGRADE=false: NOT releasable"
        else
          record "container image" PASS "built, healthy, hardened flags, 401 when anonymous"
        fi
      else
        record "container image" FAIL "started but health=${HEALTH:-none} anonymous=${UNAUTH:-none}"
      fi
    else
      record "container image" FAIL "docker build failed — see ${EVIDENCE}/docker-build.txt (TLS proxy? set ART_BUILD_CA_BUNDLE)"
    fi
  fi
else
  record "container image" SKIP "pass --with-docker to build and smoke-test it"
fi

# --- verdict ---------------------------------------------------------------------------------
"${PY}" scripts/evidence_summary.py final --dir "${EVIDENCE}"
STATUS=$?
if [ "${STRICT}" = 1 ] && grep -q $'\tDEGRADED\t' "${STEPS}"; then
  log "--strict: a step ran with reduced coverage, failing the run"
  STATUS=1
fi
log "evidence bundle: ${EVIDENCE}/ (start with ${EVIDENCE}/SUMMARY.md)"
exit "${STATUS}"
