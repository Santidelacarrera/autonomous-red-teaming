# Threat model of the simulator

| Threat | Impact | Likelihood | Mitigation | Detection | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Credential compromise / token theft | Account impersonation | Medium | Short-lived IdP tokens, TLS, memory-only browser token, IdP revocation | Authentication anomalies and correlated audit | Browser or endpoint compromise remains an IdP/endpoint responsibility. |
| Session hijacking | Unauthorized console access | Medium | Bearer model avoids ambient cookies; PKCE adapter boundary; no persistent token storage | Repeated subject/request anomalies | XSS or compromised browser runtime can access in-memory tokens. |
| JWT algorithm confusion / `none` | Forged identity | Low | Asymmetric algorithm allow-list and mature JWT library | Authentication failure spikes | Provider/library vulnerabilities require patching. |
| Issuer or audience confusion | Cross-service token acceptance | Low | Exact configured `iss` and `aud` validation | Authentication failures | Misconfigured provider values remain operational risk. |
| JWKS/key substitution | Forged signature | Low | HTTPS JWKS, `kid`, signature-use checks, bounded cache and unknown-key refresh | Unknown-key/authentication failures | DNS/TLS trust and IdP compromise remain external. |
| Privilege/RBAC/permission bypass | Unauthorized simulation or administration | Medium | Local role-permission matrix and backend complete mediation | Authorization-denied and admin audit events | Application bugs require regression tests and review. |
| Approval forgery or replay | Unauthorized simulated workflow progression | Medium | Permission, optional MFA, rate limit, durable CAS, lifecycle and HMAC evidence | Approval and denial events by run/request ID | Key rotation and external immutable retention are deployment concerns. |
| Brute force / account enumeration | Credential abuse and identity discovery | Medium | Generic 401/403, IdP login, authentication rate limit | Authentication failure and rate-limit counters | Distributed abuse needs edge/WAF controls. |
| Rate-limit bypass | Resource exhaustion | Medium | Provider-neutral subject/network policies; production requires shared adapter | `rate_limit_exceeded_total` | Development in-memory state is process-local. |
| CSRF | Unauthorized state-changing request | Low in bearer model | No ambient auth cookie; explicit Authorization header; constrained CORS | Unexpected origin and authorization events | A future cookie/BFF design needs anti-CSRF controls. |
| CORS misconfiguration | Browser-origin data exposure | Medium | Explicit validated allow-list, no wildcard, credentials disabled | Preflight failures/config review | Non-browser clients are controlled by authentication, not CORS. |
| Secret leakage | Database, IdP, GitHub or approval compromise | Medium | `SecretStr`, `SecretProvider`, ignored `.env`, safe errors and typed audit | Secret scanning and log review | Managed secret storage/rotation is deployment-owned. |
| Audit tampering | Loss of accountability | Medium | Append-only ports and typed events | Sequence/retention monitoring | In-memory development audit is not durable; production SIEM is external. |
| Prompt injection / graph poisoning | Misleading simulated plan | Medium | Sanitized allow-listed topology, Shadow scope, bounded paths | Supervisor findings and graph versions | Source provenance remains a gap. |
| Cypher injection | Unauthorized graph query | Low | Parameters, static queries and strict validator | Query failure telemetry | Database least privilege remains required. |
| Checkpoint tampering | Invalid workflow resume | Low | Integrity hash, schema validation, HMAC approval evidence | Corruption errors | Filesystem administrator can alter local data. |
| Real-infrastructure mutation | Operational harm | Low | Simulation-only APIs, Shadow graph, proposal-only artifacts, no apply/deploy controls | Scope violations and code review | Deployment credentials must still follow least privilege. |
