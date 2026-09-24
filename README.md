# Autonomous Red Teaming & Attack Graph Simulator

Defensive BAS/CTEM platform for deterministic, Shadow-only simulation of cloud
and Kubernetes attack paths. It models topology in Neo4j, analyzes bounded
paths, creates review-only remediation candidates, and verifies them against an
in-memory simulated graph. It never executes exploits, obtains credentials,
applies infrastructure changes, or publishes a pull request without a separate
explicit integration call.

## Architecture

```text
FastAPI -> durable run -> dispatcher -> worker -> LangGraph simulation
                                          -> risk / blast-radius analysis
                                          -> normalized remediation
                                          -> durable human approval checkpoint
                                          -> simulated verification
                                          -> immutable result + Markdown report
```

- `domain`: Pydantic entities, repository contract, and safe errors.
- `infrastructure`: async Neo4j and GitHub adapters with validation/retry.
- `agents`: LangGraph recon, planner, supervisor, and mock simulator.
- `attack`: reproducible in-memory path and risk engines.
- `remediation`: normalized candidates, exporters, approval, and verification.
- `worker`: durable claims, checkpoint recovery, Shadow workflow orchestration,
  immutable result commits, a development process dispatcher, and provider-neutral
  broker message/transport contracts.
- `blast_radius`, `reporting`, `observability`: quantitative analysis, report
  rendering, lightweight spans, agent timings, and aggregate metrics.

See the real component boundaries and dependency graph in
[docs/architecture.md](docs/architecture.md).

The operational layer persists secret-free `SimulationRun` records, execution leases,
append-only audit events, immutable results, and versioned workflow snapshots through
provider-neutral ports. The baseline SQLite adapter uses WAL and transactional
compare-and-set for a single-node deployment; it remains separate from Neo4j's Shadow
topology. The official async LangGraph saver shares the development database file but
owns independent checkpoint tables.

## Security boundaries

- Only the `shadow` environment is accepted by the orchestrator.
- Graph data passed toward planning is allow-listed; names, tags, logs,
  relationship properties, scanner output, and Kubernetes payloads are omitted.
- `CONTAINER_ESCAPE`, `CREDENTIAL_ACCESS`, and `IAM_ASSUME_ROLE` are simulated
  graph relations, not operational capabilities.
- Remediation exporters generate review artifacts only. Terraform/OpenTofu are
  `locals` blocks, IAM output is unattached, and Gatekeeper output is opt-in.
- Human approval is a checkpointed LangGraph interrupt before simulated
  verification. Rejected candidates end without applying a modeled change.
- Verification removes an edge only from an immutable in-memory graph copy and
  recomputes path reachability, risk, and blast radius.
- Approval evidence is HMAC-bound to the workflow and remediation; forged state
  cannot unlock simulated verification. The workflow enforces a typed lifecycle.

## Setup and base Shadow E2E

Use Python 3.11+ and configure a Shadow-only Neo4j database in `.env`:

```dotenv
NEO4J_URI=neo4j+s://example.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=replace-me
```

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe scripts\seed_db.py
.\.venv\Scripts\python.exe scripts\run_e2e.py
```

`seed_db.py` is idempotent and only creates the sample Shadow topology. The
base E2E reads that graph, runs mock simulation, and renders a remediation
candidate in memory; it does not export, apply, or publish it.

## Advanced simulated flow

The unit end-to-end scenario covers a synthetic path:

```text
Container -> CONTAINER_ESCAPE -> Node -> CREDENTIAL_ACCESS
          -> SyntheticCredential -> IAM_ASSUME_ROLE -> Role -> ACCESS -> Crown Jewel
```

It verifies that a path exists before, the chosen relation is removed only in a
graph copy after approval, path reachability disappears, risk decreases, blast
radius decreases, and a Markdown report is rendered from the resulting data.

Supported review exporters are JSON, Terraform HCL, OpenTofu HCL, OPA/Rego, and
Gatekeeper `ConstraintTemplate`. PDF is intentionally not included because no
PDF renderer dependency is present; Markdown is the canonical report artifact.

## Risk scoring

`RiskScoringSettings` centralizes all weights. The bounded 0–100 score sums
criticality, CVSS, relation severity, crown-jewel reachability, credential
exposure, and container escape, then subtracts a configurable path-length
penalty. `RiskBreakdown` stores every component; no opaque score is emitted.
CVSS scores are constrained to `0.0..10.0`; vectors are structurally validated as
CVSS v3.0/v3.1. A complete vector-to-score consistency parser is intentionally out
of scope; see [hardening audit](docs/hardening.md) for the formula and limitation.

## Hardening audit

The phase-6 audit adds regression coverage for deep-copy isolation, parallel Shadow
branches, approval bypass attempts, forged state, lifecycle transitions, CVSS input,
and bounded traversal edge cases. See [docs/hardening.md](docs/hardening.md).

## Configuration and development

`NEO4J_PASSWORD`, GitHub tokens, and `approval_secret` are secrets. The approval
workflow requires an injected HMAC secret of at least 32 bytes and fails closed if it
is absent. `.env` is ignored by Git; see [configuration](docs/configuration.md) for the
current settings boundary and local `EnvironmentSecretProvider`.

Set `ART_SIM_APPROVAL_SECRET` to at least 32 bytes before composing a production-style
approval workflow. `OperationalSettings` selects `development`, `staging`, or
`production` explicitly and validates its SQLite location, logging level, workflow
version, and secret name before work begins.

The primary executable is [scripts/run_e2e.py](scripts/run_e2e.py): it reads the
configured Shadow graph, runs LangGraph's mock simulation, and renders an artifact in
memory. `seed_db.py` is a separate idempotent **write** helper restricted to a Shadow
database; do not run it against production.

## API platform

The versioned FastAPI adapter lives in `art_sim.api`; it is thin and delegates durable
run creation, approval CAS, and reads to application services. Start its development
composition with:

```powershell
$env:ART_ENV = "development"
python -m uvicorn art_sim.api.main:app --host 127.0.0.1 --port 8080
```

Use the OpenAPI document at `/openapi.json`. Development authentication requires a
deliberate header token and is rejected for production composition. Detailed endpoint,
security, idempotency, lifecycle, and persisted-result semantics are in
[API documentation](docs/api.md). The local composition starts an asynchronous process
worker, resumes durable checkpoints after restart, and serves results only after
terminal `SUCCEEDED`.

Identity is provider-neutral and authorization is permission-based in the backend.
Local development retains the explicit development bearer format; non-development
profiles require an externally composed OIDC/JWT provider and fail closed. See the
[security architecture](docs/security-architecture.md), [authentication](docs/authentication.md),
[authorization](docs/authorization.md), and [security operations](docs/security-operations.md).

Production has a separate `create_production_app(...)` dependency-injection root. It
accepts only explicit OIDC, distributed rate-limiter, durable audit, secret-provider,
operational-store, and distributed-dispatcher dependencies; it rejects the local process
dispatcher, SQLite, environment-only secrets, and process telemetry. It does not
construct or pretend to connect Redis, a broker, SIEM, a cloud secret manager, or a
server database. Required MFA derives exclusively from an
explicitly configured claim in a signature-verified OIDC token.

## Command Center frontend

The React/Vite Command Center is an API-only dark operations interface for
observing and requesting **defensive, Shadow-only** simulations. It shows
bounded API pages, controlled scenario creation, run detail, API-provided risk,
the existing simulated approval gate, and persisted analysis results. The detail view
polls all active lifecycle states, stops at terminal state, and uses bounded backoff for
transient network or rate-limit responses. Results not yet persisted by a worker are
explicitly shown as unavailable; the UI never creates placeholder security findings or
attack paths.

```powershell
# terminal 1
$env:ART_ENV = "development"
python -m uvicorn art_sim.api.main:app --host 127.0.0.1 --port 8080

# terminal 2
Set-Location frontend
npm ci
npm run dev
```

Vite proxies the local API by default. The protected development login uses the
existing memory-only `development:<role>:<subject>` bearer format and validates it
against the backend identity endpoint. See
[frontend documentation](docs/frontend.md) for roles, API configuration,
deployment boundary, tests, and the no-infrastructure-action guarantee.

## Limitations and production gaps

The repository now contains a durable single-process development worker with execution
CAS, leases, bounded recovery, official LangGraph checkpoint resume, restart-safe HITL,
immutable result persistence, fencing tokens, cooperative cancellation, versioned broker
messages, and external-adapter contracts. It is not a distributed production service. A real
broker/dispatcher, separately deployed workers, server-database coordination, managed
secrets, external telemetry, and deployment configuration remain external work. See
[worker architecture](docs/worker.md), [workflow orchestration](docs/workflow-orchestration.md),
[result persistence](docs/result-persistence.md), and
[production readiness](docs/production-readiness.md).
Phase 12 details are in [distributed execution](docs/distributed-execution.md),
[worker recovery](docs/worker-recovery.md), [operational store](docs/operational-store.md),
and [dispatcher](docs/dispatcher.md).
The exact tested surface is in [test matrix](docs/test-matrix.md) and the simulator's
own attack surface is in [threat model](docs/threat-model.md).

Any credential exposed outside its intended boundary, including a Neo4j password, must
be rotated by an operator. The project does not print that value, modify `.env`, or
perform an external rotation automatically.

## Validation

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy .
```
