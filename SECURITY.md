# Security Policy

## Scope and intent

This project is a **defensive** Breach-and-Attack-Simulation / CTEM platform. All
topology, attack paths, credentials, and remediation are simulated against an isolated
Shadow Graph. It does not execute attacks against real infrastructure, and it is not an
exploitation framework. See the "Security Boundary" section of the [README](README.md).

## Supported versions

Security fixes are applied to the `main` branch. Pin deployments to a reviewed commit
and the published supply-chain evidence (SBOM + build provenance) produced by CI.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- Open a GitHub private security advisory ("Report a vulnerability") on this repository, or
- Email the maintainers with details and reproduction steps.

Do **not** open a public issue for an undisclosed vulnerability.

We aim to acknowledge reports within 3 business days and to provide a remediation
timeline after triage. Please allow coordinated disclosure before publishing details.

## Handling secrets

- Never commit real credentials. `.env` is git-ignored; use `.env.example` /
  `.env.production.example` as non-secret templates.
- Production secrets (approval HMAC, database DSN, broker credentials, OIDC client
  secret) are resolved at runtime through an external secret provider and must be
  distinct from one another.
- If a credential is ever exposed, **rotate it immediately** rather than only removing
  the file.

## Automated security controls in CI

Every push and pull request runs:

- `bandit` — static analysis of first-party Python source.
- `pip-audit` / `npm audit` — dependency vulnerability scanning (Python + frontend).
- `gitleaks` — secret scanning across full git history.
- `grype` — container image vulnerability scanning (fails on High+).
- CycloneDX SBOMs (Python, frontend, container) and SLSA build-provenance attestation.

## Runtime security posture

- Fail-closed configuration: non-development profiles require OIDC, HTTPS CORS, HSTS,
  a distributed rate limiter, a durable audit sink, and an external secret provider.
- OIDC access tokens are verified by signature, `kid`, approved asymmetric algorithm,
  issuer, audience, and time claims against a rotating JWKS.
- Strict response headers (CSP, `X-Content-Type-Options`, `Referrer-Policy`,
  `X-Frame-Options`, `Permissions-Policy`, optional HSTS) and a request body size limit.
- Human approval plus automated pre-approval is required before any remediation
  countermeasure, and optional step-up MFA can gate sensitive actions.
