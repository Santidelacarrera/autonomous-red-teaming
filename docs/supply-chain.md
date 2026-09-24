# Supply chain

Direct dependencies and compatible version ranges are declared in `pyproject.toml`.
There is no lockfile yet, so exact transitive reproducibility remains a gap. CI installs
the declared development dependencies, runs `pip-audit`, runs Gitleaks, and builds a
wheel; it does not deploy infrastructure.

Before a production release, generate and review a pinned lockfile using the selected
package-management workflow, retain SBOM/provenance as release artifacts, and scan the
container image in the deployment pipeline. Dependency upgrades are intentionally not
performed by this phase.
