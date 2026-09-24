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
| POST | `/api/v1/simulations` | `simulation:create` | Creates a durable run and dispatches it after commit; accepts `Idempotency-Key`. |
| GET | `/api/v1/simulations` | `simulation:read` | Bounded `limit`/`offset` list, optional status filter. |
| GET | `/api/v1/simulations/{run_id}` | `simulation:read` | Returns durable run state. |
| POST | `/api/v1/simulations/{run_id}/approval` | `simulation:approve/reject` | Rate-limited durable CAS and optional MFA policy. |
| POST | `/api/v1/simulations/{run_id}/cancel` | `simulation:cancel` | Idempotent cooperative cancellation; never kills a worker directly. |
| GET | `/api/v1/simulations/{run_id}/events` | `audit:read` | Safe lifecycle timeline without metadata payloads or ownership internals. |
| GET | `/api/v1/simulations/{run_id}/risk` | `risk:read` | Exposes persisted before/after values only. |
| GET | analysis/remediation/verification/report paths | corresponding read permission | Reads immutable persisted results; returns `409` until success. |
| GET | `/api/v1/security/status` | `security:admin` | Safe posture, counters and redacted recent events. |

The concrete result paths are `/risk`, `/attack-paths`, `/blast-radius`,
`/remediations`, `/verification`, and `/report` below the simulation resource. They
intentionally do not regenerate or fabricate findings. `CREATED`, `RUNNING`,
`WAITING_APPROVAL`, `RESUMING`, and every non-successful terminal state return
`409 RESULT_NOT_AVAILABLE`.

## Example

```powershell
$headers = @{ Authorization = "Bearer development:operator:alice"; "Idempotency-Key" = "local-request-0001" }
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/v1/simulations -Headers $headers -ContentType application/json -Body '{"scenario_id":"shadow-demo"}'
```

The response is `202` with a durable `run_id` and `created` flag. The local development
composition activates its worker asynchronously; the HTTP request never runs the
workflow inline. An approval-required run advances to `waiting_approval`; only then can
the approval endpoint record one decision by compare-and-set and dispatch a resume.
Reusing an idempotency key returns the original run and does not execute it twice; the
key cannot be reused for a different scenario.

Production composition requires an explicitly injected distributed dispatcher. It
rejects the process-local dispatcher and does not invent a broker connection.

Cancellation returns `200` for the first valid request and an idempotent already-cancelled
request. Cancelling another terminal state returns `409`. `RUNNING` and `RESUMING` record
a request for the fenced worker; idle `CREATED` and `WAITING_APPROVAL` runs can become
`CANCELLED` immediately. Cancelled runs never expose fabricated results.

## Security contract

Every response has `X-Request-ID`; valid client-supplied IDs are accepted, injected IDs
are replaced. Requests above 64 KiB are rejected from `Content-Length`, pagination is
limited to 1–200, CORS is deny-by-default, and responses use `Cache-Control: no-store`,
`nosniff`, frame denial, no-referrer, restrictive CSP and Permissions Policy. HSTS is
enabled only by a validated HTTPS production profile.
Expected errors use `{ "error": { "code", "message", "request_id" } }` without stack
traces, filesystem paths, raw bodies, or secrets.
