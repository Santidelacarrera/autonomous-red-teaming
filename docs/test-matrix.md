# Test matrix

## Executed local baseline

| Suite | Command | Result |
| --- | --- | --- |
| Backend | `.\.venv\Scripts\python.exe -m pytest -q` | PASS — 121 |
| Ruff | `.\.venv\Scripts\python.exe -m ruff check .` | PASS |
| Mypy strict | `.\.venv\Scripts\python.exe -m mypy .` | PASS — 99 files |
| Frontend | `npm test -- --run` | PASS — 19 tests / 7 files |
| Frontend lint | `npm run lint` | PASS |
| Frontend typecheck | `npm run typecheck` | PASS |
| Frontend build | `npm run build` | PASS |
| Python audit | `python -m pip_audit -r requirements.lock` | PASS — no known vulnerabilities |
| npm audit | `npm audit --audit-level=high` | PASS — 0 vulnerabilities |
| Shadow E2E | `python scripts/run_e2e.py` | PASS |
| Python/frontend SBOM/hash evidence | `cyclonedx-py ...`, `npm sbom`, manifest script | PASS — ignored `var/audit/` output |
| Release configuration integrity | YAML/pin/digest validation | PASS — 11/11 Actions pinned, 2/2 Docker stages digest-pinned |
| Docker build/start/health | `docker build ...` | BLOCKED BY LOCAL ENVIRONMENT |
| Image scan | CI Anchore job | NOT EXECUTED locally |
| Gitleaks | CI secret-scan job | NOT EXECUTED locally — CLI unavailable |
| GitHub artifact provenance | commit-pinned CI attestation step | CONFIGURED — NOT EXECUTED in hosted CI |

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
| Checkpoint missing/corrupt/restart in waiting/resuming | operational store + worker tests |
| Result version conflict/rollback/immutable publication | distributed execution tests |
| External readiness outages | Phase 13 controlled failure-injection tests |
| Frontend protected routes/roles/polling/cancellation/states | Vitest suite |

No production vendor service is emulated as evidence of a real integration. No load
benchmark, coverage percentage, hosted CI result, container scan result, RPO or RTO is
claimed by this local audit.
