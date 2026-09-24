# Hardening and production-readiness audit

> Historical Phase 6 audit. Current production/security status is maintained in
> `production-readiness.md`, `threat-model.md`, and `test-matrix.md`.

## Security conclusions

The simulator remains a **Shadow-only, non-operational** system. `SimulatedAttackGraph`
has no Neo4j driver or repository dependency. Verification accepts only this in-memory
value object and creates a deep fork before removing a modeled edge. Consequently its
analysis cannot write AuraDB/Neo4j, Kubernetes, AWS, GitHub, or an IaC backend.

`tests/unit/test_hardening.py` proves that nested relationship maps are isolated,
edge removal and property replacement affect only a shadow copy, rollback uses an
untouched snapshot, and concurrent branches do not share mutable data.

## Approval and lifecycle controls

The LangGraph workflow pauses before the approval node. It only resumes after its
public `decide` operation records a non-empty operator and reason. Approval evidence
is bound by an HMAC to the run, remediation, operator, decision, and timestamp; a
forged state therefore cannot reach verification. Rejected work terminates before
simulation.

An `approval_secret` of at least 32 bytes is mandatory; its absence fails closed.
For a multi-process deployment, inject a stable secret from the platform secret manager
and use a durable LangGraph checkpointer. `MemorySaver` remains an in-process default
and does not provide cross-restart resume durability.

The integrated lifecycle is:

```text
CREATED -> ANALYZING -> REMEDIATION_PENDING -> AWAITING_APPROVAL
  -> APPROVED -> APPLIED_SIMULATED -> VERIFYING -> VERIFIED | FAILED
  -> REJECTED
```

The typed state machine rejects invalid transitions. `APPROVED`,
`APPLIED_SIMULATED`, `VERIFYING`, and `VERIFIED` require an approved record.
`VERIFIED` additionally requires a `VerificationResult` whose status is `verified`.

## Risk formula and validation

The final score is bounded to `[0, 100]`:

```text
clamp(
  criticality + CVSS + relationship + crown-jewel
  + credential-exposure + container-escape - path-length-penalty
)
```

The default maximum component contributions are 25, 30, 20, 15, 5, and 5
respectively. All weights and penalties are bounded non-negative Pydantic fields;
the score calculation contains no clock, random input, or graph iteration ambiguity.

`cvss_score` is constrained to `0.0..10.0`. When supplied, `cvss_vector` must match
the structural form of a CVSS v3.0/v3.1 vector. This project deliberately does **not**
implement a full CVSS parser and therefore does not derive or cross-check a numerical
score from that vector. Consumers requiring score/vector consistency must validate
with a dedicated CVSS library before constructing `Vulnerability`.

## Traversal limits

The attack-path engine is deterministic bounded BFS. It sorts outbound edges by target
identifier and relationship type, tracks visited nodes to terminate cycles, and rejects
depth limits outside `1..32`. Regression coverage includes linear, cyclic, dense,
no-crown-jewel, multiple-crown-jewel, nonexistent-source, and depth-limited graphs.

## Verification command

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m mypy src tests
```
