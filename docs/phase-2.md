# Phase 2 — LangGraph orchestration

```text
START -> recon -> planner -> supervisor -- approved --> simulator -> END
                                      \-- rejected --> planner
                                      \-- retry limit --> END
```

The graph only passes `SanitizedTopologyContext` to a planner: asset names,
tags, relationship properties, scanner evidence, logs, and Kubernetes payloads
are omitted. `SupervisorAgent.audit` independently raises `ScopeViolationError`
for non-Shadow environments, assets outside the allow-list, or non-simulation
actions. The graph catches the structured failure, records it, and re-plans only
within the configured retry budget. `MockExecutionSimulator` has no shell,
network, cloud, or exploit capability.
