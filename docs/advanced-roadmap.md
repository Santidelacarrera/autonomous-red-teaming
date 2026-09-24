# Advanced phases: threat modeling, remediation, and reporting

## Phase 3 — simulated threat modeling

`RelationshipType` includes `CONTAINER_ESCAPE`, `CREDENTIAL_ACCESS`,
`IAM_ASSUME_ROLE`, and `ACCESS`. Vulnerability data supports CVSS vector,
simulated exploit availability, component, and fixed version while keeping
original fields compatible. `RiskScorer` accepts injected `RiskScoringSettings`
and returns a named component breakdown.

`SimulatedAttackGraph` is the verification fixture and contains no networking,
shell, cloud, credential, or exploit code. It performs deterministic, bounded
BFS only.

## Phase 4 — remediation and approval

`NormalizedRemediation` is the intermediate representation. Exporters render
JSON, Terraform, OpenTofu, OPA/Rego, and Gatekeeper artifacts from it. All
output is review-only.

`HumanApprovalWorkflow` uses LangGraph `MemorySaver` and interrupts before its
approval node. Call `start`, inspect checkpointed state, then call `decide`
with an explicit operator, reason, and decision. Only approval continues to
`RemediationVerifier`; rejection terminates. Verification mutates neither
Neo4j nor an external provider.

## Phase 5 — impact, report, observability

`BlastRadiusCalculator` calculates reachable assets, critical assets, crown
jewels, and denominated percentages over a simulated graph. The Neo4j
repository also exposes one bounded aggregate read query for live Shadow
topology measurement.

`MarkdownReportRenderer` generates executive, technical path/risk,
blast-radius, approval, verification, before/after, evidence, and telemetry
sections from typed result data. `Tracer` provides structured in-memory spans,
agent events, and aggregate metric snapshots ready for future OpenTelemetry.
