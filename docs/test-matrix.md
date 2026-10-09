# Test matrix

## Executed local baseline

| Suite | Command | Result |
| --- | --- | --- |
| Backend | `python -m pytest -q` (or `bash scripts/reproduce.sh`) | PASS — 600 passed, 2 skipped, with real PostgreSQL 16 and Redis 7 (2026-10-09; the historical 122-test baseline below predates Phases 10-16) |
| Ruff | `.\.venv\Scripts\python.exe -m ruff check .` | PASS |
| Mypy strict | `python -m mypy .` | PASS — 162 files |
| Frontend | `npm test -- --run` | PASS — 20 tests / 8 files |
| Frontend lint | `npm run lint` | PASS |
| Frontend typecheck | `npm run typecheck` | PASS |
| Frontend build | `npm run build` | PASS |
| Python audit | `python -m pip_audit -r requirements.lock` | PASS — no known vulnerabilities |
| npm audit | `npm audit --audit-level=high` | PASS — 0 vulnerabilities |
| Shadow E2E | `python scripts/run_e2e.py` | PASS |
| Python/frontend/image SBOM + hash evidence | CycloneDX generators + manifest script | PASS — 8 hashed evidence files under ignored `var/audit/` |
| Release configuration integrity | YAML/pin/digest validation | PASS — 11/11 Actions pinned, 2/2 Docker stages digest-pinned |
| Docker build/start/health/readiness/SIGTERM | hardened local image execution | PASS — healthy, HTTP 200/200, exit 0 |
| Container runtime security | inspect + `/proc/1/status` + write probes | PASS — UID 10001, zero capabilities, NNP/seccomp, read-only rootfs |
| Image scan | Grype 0.119.0, threshold `high` | FAIL — 0 Critical, 50 High, exit 2 |
| Image SBOM | Syft 1.52.0 CycloneDX 1.7 | PASS — 2,941 named/ref components |
| Gitleaks | `scripts/reproduce.sh` (Go-built v8.18.4) and CI `gitleaks-action` | PASS locally (full history); CI gate unchanged |
| GitHub artifact provenance | commit-pinned CI attestation step | CONFIGURED — NOT EXECUTED in hosted CI |

## Added 2026-10-09

| Suite | Tests | What it proves |
|---|---:|---|
| `tests/security/test_approval_controls.py` | 30 | review window (incl. boundary), permissions, replay, HMAC signature tampering |
| `tests/security/test_org_isolation.py` | 51 | tenant mediation on all 11 run routes, role matrix, OIDC organization claim |
| `tests/security/test_audit_integrity.py` | 21 | gaps, duplicates, edits, reordering, torn writes, truncation, SIEM loss/duplication |
| `tests/integration/test_state_integrity.py` | 95 | invalid transitions leave all tables unchanged (SQLite + PostgreSQL) |
| `tests/integration/test_checkpoint_recovery.py` | 6 | mid-graph crash recovery equals an uninterrupted run |
| `tests/unit/test_checkpoint_serde.py`, `test_risk_explain.py` | 9 + 14 | checkpoint allow-list; risk justification reconciles with the score |
| `tests/integration/test_demo.py` | 14 | the demo is deterministic, honest, self-contained and self-checking |
| Real services: `test_postgres_*`, Redis suites, `test_otel_collector.py`, `test_vault_real.py` | — | see [integrations.md](integrations.md) |

Tests that need a service **skip visibly** (never pass silently) and CI fails when they were
skipped: see `scripts/evidence_summary.py junit --fail-on-skip`.

## Coverage by invariant

| Area | Evidence |
| --- | --- |
| Domain validation / CVSS / sanitization | unit tests |
| Cypher allow-list and deterministic shortest path | unit tests + Shadow E2E |
| LangGraph planner/supervisor scope | unit tests + Shadow E2E |
| Risk / attack paths / blast radius | unit tests + persisted API integration |
| Remediation proposal / simulated verification / report | unit tests + integration |
| OIDC/JWT/JWKS/issuer/audience/exp/nbf/iat/algorithm | security suite with local signed fixtures |
| RBAC/MFA/HMAC/replay/approval CAS | security + persistence tests |
| Request bounds/CORS/headers/rate limiting/idempotency | API/security tests |
| Message schema/deduplication/retry/poison/DLQ | distributed execution tests |
| One owner/lease expiry/heartbeat/fencing/stale worker | concurrency/recovery tests |
| Cancellation idempotency and transition race | distributed + API integration tests |
| Checkpoint missing/corrupt/restart in waiting/resuming | operational store + worker tests; mid-graph crash recovery; wiped / rotated-secret checkpoints fail closed |
| Approval expiry / organization isolation / audit chain | see docs/security-controls.md |
| Result version conflict/rollback/immutable publication | distributed execution tests |
| External readiness outages | Phase 13 controlled failure-injection tests |
| Frontend protected routes/roles/polling/cancellation/states | Vitest suite |

No production vendor service is emulated as evidence of a real integration. No load
benchmark, coverage percentage, hosted CI result, container scan result, RPO or RTO is
claimed without local or hosted evidence. The local container scan is explicitly recorded
as failed and blocks release promotion.
