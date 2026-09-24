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
Development adapters are deliberately local or in-memory. Production composition must
inject OIDC, a shared rate limiter, and a durable audit sink and must use an explicit
CORS allow-list. The shipped `art_sim.api.main` entry point rejects non-development use.

Security decisions follow complete mediation: every protected endpoint requires an
explicit `Permission`. The local role matrix is authoritative, so token-supplied custom
permission claims cannot grant capability. HITL approval additionally retains durable
CAS, state validation and the separate HMAC-bound workflow evidence.

The in-memory limiter and security-event sink support development and tests only. Their
ports are designed for Redis/API Gateway and immutable SIEM/server-database adapters.
SQLite remains a single-node operational store and is not represented as multi-node.
