# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Container image now closes every fixable OS CVE: the runtime stage runs `apt-get upgrade`
  (66 High → 0 fixable High/Critical), and `.grype.yaml` enforces an `only-fixed`, fail-on
  `high` policy with one documented CPython pre-release disposition.
- Runtime dependencies are hash-pinned; the image is built with `--require-hashes`, so the
  build fails if any dependency is tampered with or a hash is missing.
- Added CodeQL (`security-extended`) analysis for Python and TypeScript, Dependabot weekly
  updates (pip, npm, GitHub Actions, Docker), and a pre-commit config (ruff, bandit,
  gitleaks, private-key detection).
- Added Bandit static analysis to CI and a strict Content-Security-Policy injected into the
  production frontend build.
- Added `SECURITY.md` (disclosure policy and secret handling).

### Added
- `docker-compose.yml` for a one-command hardened local stack (optional Neo4j under the
  `shadow` profile) and a `Makefile` task runner.
- MIT `LICENSE` with a non-binding defensive-use notice.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, this changelog, issue/PR templates, `CODEOWNERS`, and `.editorconfig`.

### Changed
- README elevated with badges, a 60-second quickstart, a verified-operational section, and
  updated supply-chain / production-readiness status (NOT READY only pending external infra).

### Verified
- 158 backend tests, 20 frontend tests, Ruff, strict Mypy (100 files), Bandit (0 findings),
  pip-audit, npm audit, Gitleaks (full history, 0 leaks), and the Grype image gate all pass.
- End-to-end Shadow pipeline validated against a live Neo4j instance: seed → recon → MITRE
  planning → simulation → human approval → verification, reducing simulated risk 51.0 → 0.0.

### Confirmed (hosted)
- GitHub Actions `ci`, `codeql`, and `scorecard` workflows pass on `main` (hosted runners),
  including container build, Grype `high` gate, SBOMs, and build-provenance attestation.

### Security (defense-in-depth)
- Hardened the Cypher validator: `CREATE`/`REMOVE` forbidden outright and write clauses
  (`MERGE`/`SET`) rejected under read intent, so a read can never mutate the graph even if
  the forbidden list is relaxed. Added 33 adversarial tests (all real production queries
  pass; 24+ injection attempts fail closed). Backend suite now 158 tests.
