# API v1

The API is a thin FastAPI adapter over application services and durable repositories.
It exposes simulation coordination and proposals only: no endpoint applies Terraform,
OpenTofu, IAM, Kubernetes, or cloud changes.

## Local development

```powershell
$env:ART_ENV = "development"
$env:ART_SIM_OPERATIONAL_DB = "var/art-sim/operations.sqlite3"
python -m uvicorn art_sim.api.main:app --host 127.0.0.1 --port 8080
```

The local header identity provider is intentionally development-only. Send
`Authorization: Bearer development:operator:alice` for an operator or
`Bearer development:viewer:bob` for read-only access. A production profile fails to
start through this entry point. Production composition requires the OIDC provider,
shared rate limiter, durable security audit sink and explicit CORS allow-list.

OpenAPI is available at `/openapi.json`; interactive docs are provided by FastAPI at
`/docs` in this local composition.

## Endpoints

| Method | Path | Permission | Behavior |
| --- | --- | --- | --- |
| GET | `/health`, `/readiness` | public | Liveness and dependency readiness. |
| GET | `/api/v1/identity` | `simulation:read` | Returns the verified, secret-free identity context. |
| POST | `/api/v1/logout` | `simulation:read` | Audits local logout; the IdP adapter owns provider logout. |
| GET | `/api/v1/scenarios` | `simulation:read` | Lists controlled scenario IDs. |
| POST | `/api/v1/simulations` | `simulation:create` | Creates a durable run; accepts `Idempotency-Key`. |
| GET | `/api/v1/simulations` | `simulation:read` | Bounded `limit`/`offset` list, optional status filter. |
| GET | `/api/v1/simulations/{run_id}` | `simulation:read` | Returns durable run state. |
| POST | `/api/v1/simulations/{run_id}/approval` | `simulation:approve/reject` | Rate-limited durable CAS and optional MFA policy. |
| GET | `/api/v1/simulations/{run_id}/risk` | `risk:read` | Exposes persisted before/after values only. |
| GET | analysis/remediation/verification/report paths | corresponding read permission | Returns `409` until a worker persists the result. |
| GET | `/api/v1/security/status` | `security:admin` | Safe posture, counters and redacted recent events. |

Result endpoints intentionally do not fabricate attack paths, blast radius, remediation,
verification, artifacts, or Markdown reports. Persisted-result repositories and worker
orchestration are the next integration step.

## Example

```powershell
$headers = @{ Authorization = "Bearer development:operator:alice"; "Idempotency-Key" = "local-request-0001" }
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/v1/simulations -Headers $headers -ContentType application/json -Body '{"scenario_id":"shadow-demo"}'
```

The response is `202` with a durable `run_id` and `created` flag. A worker must advance
the run to `waiting_approval`; only then can the approval endpoint transition it exactly
once. Reusing an idempotency key returns the original run; it cannot be reused for a
different scenario.

## Security contract

Every response has `X-Request-ID`; valid client-supplied IDs are accepted, injected IDs
are replaced. Requests above 64 KiB are rejected from `Content-Length`, pagination is
limited to 1–200, CORS is deny-by-default, and responses use `Cache-Control: no-store`,
`nosniff`, frame denial, no-referrer, restrictive CSP and Permissions Policy. HSTS is
enabled only by a validated HTTPS production profile.
Expected errors use `{ "error": { "code", "message", "request_id" } }` without stack
traces, filesystem paths, raw bodies, or secrets.
