# Supply chain security

## Implemented controls

- `requirements.lock`: exact application + development dependency versions.
- `requirements-runtime.lock`: exact runtime-only dependency versions used by Docker.
- `frontend/package-lock.json`: exact npm dependency graph installed with `npm ci`.
- multi-stage Docker build installs the runtime lock and the local wheel with `--no-deps`;
- both Docker stages pin the reviewed Python image manifest list by SHA-256 digest;
- every third-party GitHub Action is pinned to a resolved full commit SHA;
- CI runs `pip-audit`, `npm audit`, Gitleaks, package build, CycloneDX SBOM generation,
  SHA-256 artifact manifest, container build, Anchore scan and container SBOM;
- CI requests GitHub build provenance for wheel/SBOM/hash artifacts on `push` using the
  platform OIDC identity and artifact-attestation service; the OIDC/attestation permissions
  exist only in a minimal post-validation job that downloads the retained evidence;
- `scripts/generate_artifact_manifest.py` rejects missing/out-of-repository inputs and
  hashes artifacts deterministically.

## Evidence boundary

The Python locks are exact but do not contain hashes because the local cross-platform
hash resolution did not complete. Artifact SHA-256 values protect produced evidence, not
dependency download provenance. Hosted CI and image scanning are workflow definitions
until a real run is inspected; they are not marked PASS by this local audit.

The base-image digest and Action commits were resolved on 2026-09-24. They are immutable
inputs but still require an explicit dependency-update process. Provenance is configured,
not validated: this local environment cannot mint a GitHub-hosted OIDC attestation. Before
promotion, execute the hosted workflow, retain SBOM/scan/hash artifacts, and verify the
attestation from a separate trust context. The container image itself is not published or
attested by this workflow, and the Python locks do not yet include download hashes.
