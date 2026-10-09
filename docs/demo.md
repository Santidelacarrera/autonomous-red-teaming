# The lab demonstration

```bash
python -m art_sim.demo --out out/demo        # or: make demo
```

One command, offline, no credentials, no network, simulation only. It writes
`out/demo/report.html` (open it in a browser) and finishes with a one-screen verdict:

```
  Attack route      : internet -> web-frontend -> api-workload -> k8s-node -> node-credentials -> deploy-role -> billing-db
  Risk              : 58.67 -> 0.00 (verification: verified)
  Blast radius      : 90% -> 50%
  Human approval    : approved by alice
  Controls held     : 16/16
  Audit chain       : intact (25 events); tamper detected: True
  Findings digest   : 0b622fa3dc81…
  Reproducibility   : REPRODUCED (findings digest + 4 file hashes match the committed reference)
RESULT: OK
```

## What it is — and is not

The estate is **fictional**: eleven `Environment.SHADOW` assets with provider `synthetic`
(a public entry point, a web tier, workloads, a node, a credential, an IAM role, two databases,
two buckets). Nothing is scanned, resolved, connected to or changed; the graph exists only in
memory. The demo does **not** reimplement the product: it composes the real FastAPI app, the
real worker, the durable LangGraph checkpoint, HMAC-signed approval and the hash-chained audit
sink, and talks to the app over ASGI exactly as a client would.

## What happens, in order

1. **alice** (operator, organization *acme*) submits the allow-listed scenario.
2. The worker finds the shortest route to the crown jewel (`billing-db ★`), scores it, proposes a
   remediation, **verifies it on a copy of the graph**, and *pauses* at the human gate.
3. The demo then **tries to bypass the gate**, and every attempt must fail: anonymous (401),
   a viewer (403), an administrator of *another* organization (404 — the run is invisible to
   them), an approval with no real review reason (422), and reading a result before anyone
   decided (409 — no result exists without a human).
4. alice approves. The worker verifies the HMAC bound to *this run, operator, decision and time*,
   only then applies the control to the simulated graph and publishes the result.
5. A **replayed** approval is refused (409); the operator role cannot read the audit trail (403)
   but an administrator can (200).
6. A second run is left waiting past its 24 h review window; a late approval is refused (**410**),
   the run is *not* auto-approved, and it is retired by cancellation.
7. The durable audit log's hash chain is verified. Then one event is deleted from a *copy* and
   verified again — the gap is detected.

## Reading the report

| Section | What to look at |
|---|---|
| Headline cards | risk, crown-jewel exposure, blast radius and verification, before → after |
| Before / after | same layout in both views: the red route is the attack path; the dashed edge is the single relation the approved control severs; dashed boxes became unreachable. Meaning is also in text (criticality, ★, "unreachable"), not only colour. |
| Why the risk is 58.67 | seven factors, each with the scorer's own value, its ceiling and the *evidence* behind it. The factors provably sum to the reported score. The CVSS factor honestly reads 0 of 30: no scanner evidence was supplied. |
| Proposed remediation | what would change, that it was applied only to an in-memory copy, and the automated pre-approval checks (a recommendation, never an authorization). |
| Human approval | who, when, why; and what the worker refused to do before it. |
| Controls exercised | every request the demo made against the running API, with expected vs observed status. |
| Audit evidence | the operational and security event trails of this run, and the chain verification. |

## Reproducing and checking it

The report has two kinds of content:

- **Findings** — graph, route, risk factors, blast radius, remediation, verification and the
  control outcomes — are deterministic (asset IDs are `uuid5` of names). They are serialized
  canonically in `findings.json`; its SHA-256 is committed in
  `src/art_sim/demo/expected_findings.sha256`, and the exact bytes of `report.md`, `before.svg`
  and `after.svg` in `expected_reproducible.sha256`. The command prints `REPRODUCED` or `MISMATCH`
  and its exit code follows. A reviewer on any machine gets the same bytes.
- **Run evidence** — run IDs, timestamps, the audit log — is real but differs every execution,
  so it is shown separately and excluded from the digest.

If you change the lab or the renderer on purpose, regenerate the references with
`python -m art_sim.demo --update-expected` and commit them; `tests/integration/test_demo.py`
fails until you do, which is the point.

## Known limitations (stated, not hidden)

- **The generated policy file is not a 1:1 implementation of the control.** The remediation
  generator picks a generic guardrail template from the *target asset's type* (here an IAM
  `sts:AssumeRole` deny for a database target), while the verified control severs a
  container-escape relation. The security effect shown comes from the graph simulation, not from
  that file. The report says so next to the artifact.
- One remediation per run, applied to the shortest route; a lab with several independent routes
  would report `partially_verified`, which is the correct (honest) outcome.
- The lab has no vulnerability data, so the CVSS factor is 0 by construction.
- The demo's development authentication (`Bearer development:<role>:<subject>#<org>`) exists only
  so the demo can act as several identities offline; production refuses it.
