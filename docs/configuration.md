# Configuration

Configuration is validated by Pydantic before work is accepted. `.env.example` is the
development template; `.env.production.example` contains non-secret production
references. Neither proves an external service is present.

## Development

| Variable | Purpose |
| --- | --- |
| `ART_ENV` | Must be `development` for `art_sim.api.main`. |
| `ART_AUTH_MODE` / `ART_AUTH_PROVIDER` | `development`; conflicting values fail. |
| `ART_SIM_OPERATIONAL_DB` | Explicit SQLite file, development only. |
| `ART_CORS_ALLOWED_ORIGINS` | Comma-separated exact local origins. |
| `ART_RATE_LIMIT_ENABLED` | Local process limiter toggle; cannot disable production limiting. |
| `ART_*_REQUESTS_PER_MINUTE` | Positive bounded endpoint policies. |
| `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` | Optional local Shadow seed/E2E; password is secret. |
| `VITE_*` | Frontend API, auth-mode and polling development settings. |

## Production identity

`SecuritySettings.from_environment()` requires `ART_AUTH_MODE=oidc`, complete HTTPS
`ART_OIDC_ISSUER`, `ART_OIDC_AUDIENCE`, `ART_OIDC_JWKS_URL`, exact CORS origins,
enabled HSTS and rate limiting. Sensitive approval can require an explicit
`ART_OIDC_MFA_CLAIM` plus accepted `ART_OIDC_MFA_VALUES`. Development auth, wildcard
CORS, HTTP origins, shared-secret JWT algorithms and incomplete OIDC config fail closed.

**Organization (tenant) claim.** Every verified token must carry the claim named by
`ART_OIDC_ORGANIZATION_CLAIM` (default `org_id`; value `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`);
a token without it, or with a malformed one, is rejected. A single-tenant deployment whose IdP
does not issue the claim must opt in with `ART_OIDC_DEFAULT_ORGANIZATION=<id>`; the
organization is never inferred and never read from request data. **This is a breaking change
for OIDC deployments that predate tenant isolation** — see the changelog.

**Review window.** `ART_APPROVAL_TTL_SECONDS` (60 – 2 592 000; production default 86 400,
development default: open-ended) bounds how long a paused simulation may wait for a human.
A decision after the window is refused (HTTP 410, `approval.expired` audit event); the run is
never auto-approved and can only be cancelled.

**Telemetry readiness.** `ART_OTLP_HEALTH_URL` (optional) is probed by readiness instead of a
plain TCP connection to `ART_OTLP_ENDPOINT`.

## Production dependencies

`ProductionDependencySettings.from_environment()` consumes:

- broker: `ART_BROKER_PROVIDER`, endpoint, queue, credential-secret name, timeout,
  visibility, in-flight and attempt bounds;
- database: provider, DSN-secret name, pool and timeout bounds;
- secrets: managed provider plus distinct approval/database/broker secret references;
- audit/telemetry/rate limit: provider family and audit retention;
- data lifecycle: simulation, result, checkpoint, DLQ and telemetry retention days;
- edge: upstream TLS, trusted proxy hops, request timeout and maximum bytes.

Only references are loaded. Actual adapters are passed to `create_production_app(...)`.
Production rejects SQLite, local dispatch, process limiting, volatile audit, environment
secrets, development identity and process telemetry.

## Secret handling and rotation

The approval HMAC value must be at least 32 bytes and is retrieved asynchronously at
startup. Database, broker and optional OIDC client credentials remain in the managed
provider. The external port supports health, atomic reload and close; it never exposes
values to audit/telemetry/jobs. Rotate by staging the new version, atomically reloading
all replicas, verifying readiness, completing or invalidating pending approval evidence,
then revoking the old version. Failed reload retains the last valid set or makes the
replica unready according to adapter policy; it must never install a partial set.
