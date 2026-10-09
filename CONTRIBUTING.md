# Contributing

Thanks for your interest in improving the Autonomous Red Teaming & Attack Graph Simulator.
This is a **defensive, simulation-only** project; contributions must preserve that scope
(see [SECURITY.md](SECURITY.md) and the README's Security Boundary).

## Ground rules

- **Simulation-only.** No change may add real exploitation, remediation apply, cloud/
  Kubernetes mutation, credential exfiltration, or offensive capability.
- **Fail closed.** New configuration and adapters must reject unsafe or incomplete setups
  rather than defaulting to a permissive mode.
- **No secrets in the repo.** `.env` is git-ignored; use the `.env.example` templates.
- **Boundaries over vendors.** Production integrations are typed ports; concrete vendor
  clients are owned by deployments, not committed here.

## Development setup

```bash
make setup          # venv + runtime and dev dependencies
make check          # ruff + mypy (strict) + bandit + pytest
make run            # dev API on :8080
cd frontend && npm ci && npm test
```

Install the local guardrails once:

```bash
pip install pre-commit && pre-commit install
```

## Before opening a pull request

Run the full quality gate and make sure everything passes:

- `make check` — lint, strict type check, SAST, and tests (122+ backend tests).
- `cd frontend && npm run lint && npm run typecheck && npm test && npm run build`.
- `make docker-scan` if you touched the Dockerfile or dependencies.

New behavior needs tests. Security-relevant changes need tests that prove the control
fails closed. Keep commits focused and write a clear description; the CI pipeline
(Ruff, Mypy, Pytest, Bandit, CodeQL, pip-audit, npm audit, Gitleaks, Grype, SBOM) must be
green before merge.

## Reporting vulnerabilities

Do not open a public issue for an undisclosed vulnerability. Follow the private process in
[SECURITY.md](SECURITY.md).
