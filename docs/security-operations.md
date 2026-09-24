# Security operations

## Controls

- API responses set no-store, nosniff, deny framing, no-referrer, a restrictive API CSP,
  and a restrictive browser permissions policy. HSTS is valid only in a non-development
  HTTPS deployment and is controlled by `ART_HSTS_ENABLED`.
- CORS uses `ART_CORS_ALLOWED_ORIGINS`; wildcard origins and path-bearing or malformed
  values are rejected. Credentials are not enabled. Bearer-header authentication avoids
  ambient cookie authentication, so CSRF does not have the same attack path. If a future
  BFF uses cookies, it must add Secure, HttpOnly, SameSite and anti-CSRF controls.
- Rate policies are explicit: `ART_AUTH_REQUESTS_PER_MINUTE`,
  `ART_SIMULATION_CREATES_PER_MINUTE`, `ART_APPROVAL_REQUESTS_PER_MINUTE`, and
  `ART_ADMIN_REQUESTS_PER_MINUTE`. Development uses an in-process limiter. Production
  must inject a distributed implementation and edge controls.
- Security counters are aggregate only: authentication success/failure, authorization
  denial, rate-limit excess, and approval denial. They contain no token or secret labels.

## Audit and alerting

Typed security events include authentication success/failure, authorization denial,
rate-limit excess, logout, simulation creation, approval decisions, and security-admin
reads. Fields are restricted to event/time/type, subject, issuer, request ID, optional
run ID, source and result. The schema cannot accept authorization headers, cookies,
tokens, passwords, keys, arbitrary metadata, or raw request bodies.

Alert on bursts of authentication failures, authorization denials, unauthorized approval
attempts, admin reads, unknown JWT key IDs, and rate-limit excess. Production must export
to immutable retention/SIEM and define retention, access review, clock synchronization,
and privacy policy. The in-memory sink is development-only.

## Incident response

For compromised identity or token: revoke sessions/tokens at the IdP, disable the account,
rotate affected keys, inspect correlated request/run IDs, and review approval events. For
issuer/JWKS compromise: stop acceptance, rotate provider keys and configuration, purge
edge caches, and validate all recent sensitive decisions. For suspicious approval:
pause workers, preserve immutable audit and checkpoint evidence, revoke the identity,
and do not resume until HMAC and lifecycle state are verified.

Secrets remain behind `SecretProvider`; production should use a managed secret service.
Never print or return approval material, IdP client secrets, database credentials, access
tokens, refresh tokens, private keys, or full authorization/cookie headers.
