# Reproducibility

Goal: **an outside reviewer can reproduce the demonstration and check the results themselves**,
from a clean clone, without trusting anything this repository says about itself.

## One command

```bash
git clone https://github.com/Santidelacarrera/autonomous-red-teaming.git
cd autonomous-red-teaming
bash scripts/reproduce.sh --with-docker        # ~5 minutes; omit --with-docker to skip the image
```

Then open `evidence/SUMMARY.md` (verdict and per-step results) and `evidence/demo/report.html`.

Prerequisites: `git`, Python ≥ 3.11 (3.12 is what CI and the lock use; 3.13 also passes).
Recommended: Docker (real PostgreSQL/Redis/Collector/Vault for the integration suites, and the
image build), Node ≥ 20 (frontend), Go (only if you want a local Gitleaks and cannot download
its release binary — see below).

`scripts/reproduce.sh` does, in order, and records each as **PASS / FAIL / SKIP / DEGRADED**:

| # | Step | What it proves |
|---|---|---|
| 1 | virtualenv from `requirements.lock` only | the lock is complete — nothing is installed "ad hoc" |
| 2 | `ruff`, `mypy --strict`, `bandit`, `pip-audit` | static quality, SAST, known-vulnerable dependencies |
| 3 | real PostgreSQL 16 + Redis 7 (reused, or throwaway containers) | integration suites really run |
| 4 | full pytest → `evidence/junit.xml` | the whole backend suite, with skips listed **with reasons** |
| 5 | frontend lint, typecheck, tests, build | the React console |
| 6 | Gitleaks over the full git history | no committed secrets |
| 7 | `python -m art_sim.demo` + audit-chain verification | the demo reproduces the committed digest; the audit log is intact |
| 8 | (`--with-docker`) image build + hardened smoke test | the container runs read-only, no capabilities, 401 when anonymous |

**DEGRADED is never hidden.** If, say, no Docker daemon is available, the database tests are
skipped by pytest — the verdict becomes `PASSED WITH REDUCED COVERAGE` and says why. Use
`--require-services` to make that a failure, `--strict` to fail on *any* degraded step.

### What the evidence bundle contains

| File | Meaning |
|---|---|
| `SUMMARY.md`, `summary.json` | verdict, commit, Python/OS, every step, test totals, skip reasons |
| `junit.xml`, `pytest.txt` | raw per-test results |
| `demo/report.html` | the demo report (open in a browser) |
| `demo/findings.json`, `findings.sha256`, `REPRODUCIBLE.sha256` | deterministic findings and hashes (see [demo.md](demo.md)) |
| `demo/audit/security.jsonl` | the durable, hash-chained audit log of the run |
| `ruff.txt`, `mypy.txt`, `bandit.txt`, `pip-audit.txt`, `gitleaks.txt`, `frontend.txt` | tool output |
| `SHA256SUMS` | hash of every file above — `sha256sum -c SHA256SUMS` |

### Checking the result independently

You do not need to trust the verdict line:

1. **Digest** — `evidence/demo/findings.sha256` must equal
   `src/art_sim/demo/expected_findings.sha256` (committed with the source). The Markdown report
   and both SVG figures must match `src/art_sim/demo/expected_reproducible.sha256`. The digest is
   machine-independent: it covers the graph, route, every risk factor, blast radius, remediation,
   verification and each control outcome, and none of the per-execution identifiers or times.
2. **Audit log** — `python scripts/verify_audit_log.py evidence/demo/audit/security.jsonl`
   re-derives the hash chain from the file alone. Delete a line and run it again: it names the gap.
3. **Tests** — open `junit.xml` in any JUnit viewer; `SUMMARY.md` lists skipped tests with reasons.
4. **CI** — every push uploads the same artifacts (`test-results`, `lab-demo`) from a clean runner.

## Local blockers we hit, and how each was resolved

These are real obstacles encountered while producing this evidence in an egress-restricted
sandbox. They are common behind corporate proxies, so they are documented rather than worked
around silently. **None required disabling TLS verification or bypassing a network policy.**

### Docker

| Symptom | Cause | Resolution |
|---|---|---|
| `failed to connect to the docker API at unix:///var/run/docker.sock` | The CLI is installed but the **daemon is not running**. | Start it: `sudo systemctl start docker`, Docker Desktop, or `sudo dockerd &` (needs root and cgroups). `docker info` must succeed. |
| `pip` in `docker build`: `CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain` | A TLS-intercepting proxy re-signs traffic; the **build container does not trust the proxy CA**. | Pass the CA as a BuildKit *secret* (never baked into a layer): `docker build --secret id=ca_bundle,src=/path/to/ca-bundle.crt .` The `Dockerfile` uses it only when supplied; default builds are unchanged. `reproduce.sh` reads `ART_BUILD_CA_BUNDLE`. |
| `apt-get update` in the runtime stage: host not resolved / CONNECT 403 | The **egress policy denies the Debian mirrors**. This is policy, not a bug — do not circumvent it. | For a *functional-only* local build use `--build-arg OS_UPGRADE=false`. That image has **not** received OS security patches and must never be released or pushed; `reproduce.sh` marks it `DEGRADED … NOT releasable`. CI and release builds always use the default (`true`). |
| `toomanyrequests` / HTTP 429 pulling `postgres`, `redis`, `python`… | Docker Hub's anonymous pull limit. | `docker login`, or point the scripts at a mirror: `ART_PG_IMAGE`, `ART_REDIS_IMAGE`, `ART_OTEL_IMAGE`, `ART_VAULT_IMAGE` (for example `mirror.gcr.io/library/redis:7-alpine`). |
| The DR drill restored into a server that "closed the connection unexpectedly" | A **race in `scripts/backup_restore_drill.sh`**: the official `postgres` image runs a temporary init server (socket-only), then restarts; `pg_isready` via `docker exec` succeeds during the first phase. | Fixed: wait for the ready banner twice *and* a TCP probe from the host. The drill then ran end to end: backup → kill source → isolated restore → row counts/checksum/`alembic_version` verified (`DR_DRILL_RESULT=PASS`). |

### Gitleaks

| Symptom | Cause | Resolution |
|---|---|---|
| `gitleaks: command not found` | Not installed. | See below. |
| Download of the release binary fails (HTTP 403 on `github.com/.../releases`) | GitHub Releases is blocked by the egress policy. | Build it from source — the Go module proxy is normally reachable: `GOBIN=.repro/bin go install github.com/zricethezav/gitleaks/v8@v8.18.4`. `reproduce.sh` does this automatically if `go` exists, or falls back to the `zricethezav/gitleaks` Docker image. |
| CI: `GITHUB_TOKEN is now required to scan pull requests` | `gitleaks-action` needs the token for PR events. | Already passed in `ci.yml`. |

Result with the pinned local build (v8.18.4): the whole git history scans clean. CI keeps running
`gitleaks-action` as the authoritative gate; the local run is a reproducible cross-check, not a
replacement.

### Python environment

`requirements.lock` was **incomplete** (its own history says alembic, SQLAlchemy and the
test-only SDKs were installed ad hoc in CI because regenerating it needed network access). It is
now regenerated with `pip-compile` under Python 3.12 and includes everything the test suite
imports, without changing any previously pinned version. Verified by installing *only* the lock
into a fresh `python:3.12` container and running the whole suite. `pip-audit` is deliberately not
in the lock: it is a scanner whose value is knowing today's advisories, so the script installs
the current release on demand.

## Verified behaviours behind the brief

| Requirement | Evidence |
|---|---|
| Recovery of an interrupted run from a checkpoint | `tests/integration/test_checkpoint_recovery.py`: a process "killed" **between two graph nodes** resumes from the LangGraph checkpoint, does **not** repeat finished work (recon runs once), and produces a result byte-identical (digest) to an uninterrupted control run. Also: crash after approval is applied → resumed, approval applied exactly once; wiped or rotated-secret checkpoints **fail closed**. |
| Invalid transitions do not modify the persisted simulation | `tests/integration/test_state_integrity.py`: for **every** forbidden `(source, target)` pair, and for each store operation attempted from a state that forbids it, a raw snapshot of all seven tables is identical before and after — on SQLite **and** real PostgreSQL. A mutation check (removing the guard) makes the suite fail. |
| Whole suite in CI with results kept | `.github/workflows/ci.yml`: JUnit uploaded as the `test-results` artifact (30 days); a job summary that **fails if database/Redis tests were silently skipped**; Redis and PostgreSQL service containers. |
| Complete clean-clone reproduction | `scripts/reproduce.sh` (above), exercised from a fresh `git clone`. |

## What this does not claim

- It does not claim bit-for-bit reproducibility of *everything*: run IDs, timestamps and the
  audit log are per-execution by nature and are excluded from the digest on purpose.
- It does not claim the container image is release-grade when built with `OS_UPGRADE=false`.
- It does not replace the hosted CI: image vulnerability scanning (Grype), provenance
  attestation and `gitleaks-action` only run there.
