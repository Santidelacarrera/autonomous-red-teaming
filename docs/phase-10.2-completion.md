# Phase 10.2: identity hardening baseline

This phase implements trusted OIDC-derived MFA, a separate fail-closed production
composition root, explicit deployment capabilities for rate limiting and audit, and
central audit redaction. It preserves the development-only local composition.

## Implemented

- Exact configurable `ART_OIDC_MFA_CLAIM` and `ART_OIDC_MFA_VALUES` interpretation after
  JWT signature, issuer, audience, time, algorithm, key ID, and JWKS validation.
- Approval enforcement combining identity, permission, optional MFA, subject rate
  limit, durable waiting-state validation, and transactional compare-and-set.
- `create_production_app(...)` with injected OIDC authenticator, distributed limiter,
  durable audit sink, secret provider, and operational store.
- Startup rejection of development auth, process-local/unlimited limiters, volatile/null
  audit sinks, incomplete OIDC, insecure CORS, disabled HSTS, or missing secret material.
- Typed MFA failure events and centralized redaction of credential-like audit strings.

## Ready with external dependency

Concrete integrations for an IdP tenant, shared limiter, immutable audit/SIEM pipeline,
managed secret service, server operational database, and HTTPS edge can implement the
published ports. No such external connection is implied by the interfaces.

## Not implemented

No Redis, SIEM, Auth0, Azure AD, Okta, cloud secret-manager, server database, or cloud
deployment adapter is bundled. No infrastructure or security control is applied to a
real environment. SQLite and in-memory adapters remain development/single-node tools.
