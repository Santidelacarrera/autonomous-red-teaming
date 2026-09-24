# Security controls

The platform remains defensive and Shadow-only. Authentication, permissions, MFA,
approval CAS, HMAC evidence, scope enforcement, and safe response envelopes remain
backend controls; the browser is never a policy enforcement point.

Production dependencies declare capabilities rather than being accepted by concrete
class name:

- verified OIDC identity provider;
- distributed rate limiter;
- durable security audit sink;
- external async secret provider;
- server-grade operational store;
- distributed dispatcher;
- external operational telemetry.

Production fails closed if any capability is absent or local-only. The approval signing
material is resolved from the named external secret during startup and must contain at
least 32 bytes. Using the same stable secret across restarts preserves verification of
pending approvals. The environment provider remains development-only.

Security audit events have a closed schema with request, run, and optional trace
correlation. Central validators redact free-text identity fields and reject
credential-shaped operational metadata. Authorization headers, JWTs, cookies, passwords,
secrets, full bodies, and arbitrary payloads cannot be accepted by the event models.

No phase-12 component can execute exploits, cloud commands, Kubernetes commands, IaC
apply operations, or real remediation.
