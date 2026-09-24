# Identity and access security architecture

```text
User -> OIDC Provider -- Authorization Code + PKCE --> React Command Center
                                                        |
                                                        | verified access token
                                                        v
Edge / reverse proxy -> CORS + TLS + distributed limits -> FastAPI
                                                        |
                     +----------------------------------+------------------+
                     | Authentication | Permissions | Security audit       |
                     +----------------------------------+------------------+
                                                        |
                           Simulation / approval / read application services
```

The backend is the policy enforcement point. The browser uses roles and permissions
only for UX; direct HTTP calls are authenticated and authorized again. `IdentityProvider`,
`RateLimiter`, `SecurityAuditSink`, and `SessionLifecycle` are provider-neutral ports.
Development adapters are deliberately local or in-memory. `create_production_app(...)`
is a separate composition root that requires verified OIDC, a limiter declaring
`DISTRIBUTED`, a sink declaring `DURABLE`, an external async secret provider, a
`SERVER_GRADE` operational store, distributed dispatch, and external telemetry. It
creates none of those deployment adapters internally. It also requires HTTPS CORS
origins and HSTS. The shipped
`art_sim.api.main` entry point continues to reject non-development use.

Security decisions follow complete mediation: every protected endpoint requires an
explicit `Permission`. The local role matrix is authoritative, so token-supplied custom
permission claims cannot grant capability. HITL approval additionally retains durable
CAS, state validation and the separate HMAC-bound workflow evidence.

The in-memory limiter and security-event sink support development and tests only. Their
ports are designed for Redis/API Gateway and immutable SIEM/server-database adapters.
SQLite remains a single-node operational store and is not represented as multi-node.

Central audit redaction replaces credential-like free text before model serialization.
The audit schema accepts neither raw headers nor arbitrary request payloads. Production
capability markers are startup assertions, not claims that Redis, SIEM, or a managed
database has been connected.

- **IMPLEMENTED:** policy enforcement, OIDC verification, MFA derivation, production DI
  root, security headers, typed audit/rate ports, and fail-closed capability checks.
- **READY WITH EXTERNAL DEPENDENCY:** distributed limiter, durable audit exporter,
  managed secrets, server operational store, TLS edge, and concrete OIDC tenant.
- **NOT IMPLEMENTED:** bundled Redis/SIEM/cloud-secret adapters or cloud deployment.
