# Phase 10 completion — Identity & Access Security

## Baseline

- Backend: 45 tests passed.
- Frontend: 7 tests passed.
- Ruff: passed.
- Mypy: passed for 67 source files.
- Frontend lint, typecheck and build: passed.

## Implemented

- Provider-neutral typed `Identity`, authentication context and identity-provider port.
- Development provider restricted to the development composition.
- OIDC/JWT resource-server provider with asymmetric algorithm allow-list, signature,
  issuer, audience, subject, issued-at, expiration, optional not-before, `kid`, HTTPS
  JWKS cache, retry and unknown-key rotation refresh.
- Central viewer/operator/admin permission matrix and backend complete mediation.
- Optional IdP-MFA step-up enforcement for simulated approval.
- Provider-neutral rate limiter with 429 and `Retry-After`; bounded in-memory development
  implementation and fail-closed production composition requirements.
- Explicit CORS allow-list and API security headers; HSTS only for validated production.
- Typed security events and aggregate security counters without credential fields.
- Identity, logout and admin-only safe security-status endpoints.
- React in-memory auth state, backend identity validation, protected application routes,
  permission-aware controls, 401 expiry, 403/429 states and logout.
- Browser OIDC adapter contract for Authorization Code with PKCE; no implicit flow or
  client secret exists in the bundle.

## Authentication

Development accepts only `Bearer development:<role>:<subject>` through the local entry
point. Non-development startup rejects this provider. Production OIDC verifies signed
access tokens using configured issuer, audience and rotating public JWKS.

## Authorization

Permissions are derived from the locally controlled role matrix, never arbitrary token
permission claims. Every protected API operation declares a permission. Approval checks
approve/reject permission, optional MFA assurance, rate policy, durable state and CAS.

## Security and audit

The API emits safe correlated authentication, authorization, rate-limit, creation,
approval, logout and admin events. It sets restrictive caching, content, framing,
referrer and permissions headers. CORS wildcard is rejected. `SecretProvider`, HMAC
approval evidence, replay protection and lifecycle validation remain intact.

## Tests

- Backend: 57 passed, including 12 dedicated security regressions.
- Frontend: 13 passed across 6 files.
- Ruff: passed.
- Mypy: passed for 77 source files.
- Frontend lint/typecheck/build: passed.
- `pip-audit`: no known vulnerabilities; local editable package is not a PyPI artifact.
- `npm audit --audit-level=high`: zero vulnerabilities.
- Shadow Neo4j E2E: passed.

## Production readiness

**READY**

- Backend permission enforcement, safe errors, security headers, explicit configuration,
  OIDC token verification, MFA context, audit/rate ports, and simulation-only boundaries.

**READY WITH EXTERNAL DEPENDENCY**

- Real IdP tenant/client and browser PKCE adapter.
- HTTPS edge/reverse proxy, distributed limiter, durable immutable audit/SIEM exporter,
  managed secret provider, token revocation policy and operational alerting.

**NOT READY**

- The local `art_sim.api.main` composition is intentionally not a production entrypoint.
- In-memory rate/audit adapters and local SQLite are not multi-node production services.

No real infrastructure was modified. No real attacks were executed. Remediation output
remained a proposal generated and verified only in the Shadow simulation path.
