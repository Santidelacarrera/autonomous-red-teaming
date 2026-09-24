# Phase 3 — Remediation engine and CI/CD

```text
approved Shadow simulation
  -> RemediationAgent (structured, sanitized prompt)
  -> deterministic policy candidate
  -> GitHubPRService
  -> branch -> commit (if content changed) -> draft pull request
```

Only approved, successful Shadow simulations enter remediation. The prompt
contains UUIDs and enums only: simulation evidence strings, logs, scanner
results, Kubernetes metadata, asset names, and tags are excluded.

The Kubernetes NetworkPolicy is opt-in: it selects only workloads explicitly
labeled with the candidate-specific remediation label. The IAM JSON policy is
unattached. Neither artifact is applied by this code. GitHub publication uses a
deterministic idempotency branch, avoids commits when the file is unchanged,
and reuses an existing open pull request when present.
