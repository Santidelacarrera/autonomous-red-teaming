# Configuration audit

| Setting | Classification | Current source | Handling |
| --- | --- | --- | --- |
| `NEO4J_URI` | Environment-specific | `.env` / process environment | Required by `scripts/seed_db.py`; not a secret. |
| `NEO4J_USER` / `NEO4J_USERNAME` | Environment-specific | `.env` / process environment | Defaults to `neo4j` only in the seed script. |
| `NEO4J_PASSWORD` | Secret | `.env` / process environment | Wrapped as `SecretStr`; never printed by project code. |
| GitHub token | Secret | caller-built `GitHubSettings` | `SecretStr`; no environment composition currently exists. |
| `approval_secret` | Secret | injected bytes | Required, at least 32 bytes; absence fails closed. |
| Neo4j pool/database/encryption | Runtime | `Neo4jSettings` | Validated Pydantic settings. |
| risk weights / depth | Runtime | typed settings / method argument | Bounded Pydantic or method validation. |
| `ART_AUTH_PROVIDER` | Security | process environment | `development` only locally; `oidc` required outside development. |
| `ART_OIDC_ISSUER`, `ART_OIDC_AUDIENCE`, `ART_OIDC_JWKS_URL` | Security/public | process environment | Complete HTTPS OIDC configuration required together. |
| `ART_CORS_ALLOWED_ORIGINS` | Security | comma-separated environment value | Explicit origins; wildcard and malformed origins fail validation. |
| `ART_RATE_LIMIT_ENABLED` and per-operation limits | Security | process environment | Explicit bounded policy; production requires a shared adapter. |
| `ART_MFA_REQUIRED_FOR_SENSITIVE_ACTIONS` | Security | process environment | Requires verified IdP MFA context for simulated approval. |
| `ART_HSTS_ENABLED` | Edge security | process environment | Production HTTPS only; rejected in local development. |

`.env`, virtual environments and cache directories are ignored by Git. No secret values
are present in tracked source, tests, reports, or telemetry fixtures. `SecretProvider`
and `EnvironmentSecretProvider` provide an infrastructure-neutral local boundary for
future AWS Secrets Manager, Vault, or Kubernetes Secret adapters. The domain does not
depend on a cloud secret SDK.

`OperationalSettings` adds explicit `development`, `staging`, and `production`
profiles, operational SQLite path, workflow version, logging level, and approval-secret
name. Configuration must resolve a non-empty approval secret of at least 32 bytes before
the approval workflow is created. Secret rotation is operationally a controlled window:
deploy the new provider value to all workers, retain the old verifier material only while
pending approvals require it, then revoke it. An approval that cannot verify under the
accepted rotation set is rejected.

Do not print `SecretStr.get_secret_value()`, commit `.env`, or use the sample seed script
against a non-Shadow database. The current repository has no feature-flag system.
