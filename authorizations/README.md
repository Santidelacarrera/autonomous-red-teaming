# Written authorizations (Nexus Security & AI Lab)

`python -m art_sim.bas` **does not run** unless a valid authorization file is supplied. This is
deliberate: offensive techniques are exercised only with the system owner's written consent,
for a named scope and a limited time.

1. Copy `local-lab.template.json` to `local-lab.json`.
2. A named person (the system owner) fills in `authorized_by`, `system_owner`, `statement`
   and the validity window (at most 90 days).
3. Set `catalogue_sha256` to the digest printed by `python -m art_sim.bas --print-catalogue-digest`
   **after reviewing** `docs/bas-scenarios.md`. A changed catalogue needs a new authorization.
4. Commit it through a reviewed change: this directory is owned in `.github/CODEOWNERS`.

Scope is always and only `["local-lab"]`: the in-process synthetic lab. A file naming any other
target (hostname, URL, address) is rejected as a whole. See `docs/bas.md` for the gate's limits.
