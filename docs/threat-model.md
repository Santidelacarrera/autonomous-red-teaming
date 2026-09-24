# Threat model

## Scope

Assets are Shadow scenarios, simulation state, approval evidence, result artifacts,
identity context, audit evidence and production adapter credentials. Real infrastructure
is outside the execution boundary and must never be reachable through a simulation job.

| Threat | Asset | Attacker | Precondition | Attack surface | Control | Detection | Residual risk / mitigation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Compromised worker | Run state/results | Runtime intruder | Worker execution compromised | Worker/store ports | Least privilege, allow-listed scenario, fenced writes, no infra credentials | Worker identity, lease and result events | A live owner can emit bad simulated output; isolate workers, attest images, review results. |
| Stale worker | Terminal state | Delayed/crashed worker | Lease expired and worker resumes | Store mutation methods | Monotonic fencing token on every worker write | `fencing_rejected`, ownership audit | Store adapter correctness is external; certify with concurrency tests. |
| Duplicate broker delivery | Run/result | Broker fault/replay | At-least-once redelivery | `SimulationJobV1` consumer | Stable message ID, durable attempt, CAS claim, immutable result | Duplicate/no-claim and broker metrics | Broker retention can amplify load; cap delivery attempts/backpressure. |
| Broker replay | Lifecycle | Broker/operator compromise | Old valid message reintroduced | Queue/topic | Version, run/scenario/workflow match, expected attempt, terminal rejection | Retry/poison/audit events | Replay still consumes capacity; apply broker ACLs and retention. |
| Database race | Approval/result | Concurrent API/workers | Same row changed concurrently | Server store | Transactions, row locks/CAS contract, one terminal transition | Conflict/fencing metrics and audit | Concrete PostgreSQL adapter needs isolation testing. |
| Lease theft | Ownership | Malicious worker | Store credential available | Acquire/renew lease | Scoped DB identity, live-owner CAS, fencing | Unexpected worker ID/lease events | Compromised DB credential remains severe; rotate and isolate. |
| Fencing failure | Result integrity | Adapter defect | Store violates token monotonicity | Server store | Capability contract, stale-worker tests, immutable publication | Multiple-owner/result invariant alert | Vendor adapter is not implemented; certification remains external. |
| Credential leakage | Secrets | User/runtime/log reader | Secret reaches input/log/response | Config, jobs, audit, telemetry | Secret references, `SecretStr`, strict schemas, redaction, safe errors | Secret scanning/log review | SDK/platform logs are external; configure redaction and rotation. |
| Token replay | Identity/session | Token thief | Valid bearer token stolen | Authorization header | TLS, expiry/nbf/iat, issuer/audience, IdP revocation boundary | Authentication anomaly/audit | Stateless API cannot revoke alone; short TTL and IdP controls required. |
| Approval replay | HITL decision | Authorized/malicious caller | Old decision/evidence replayed | Approval endpoint/store | Permission, MFA, HMAC, lifecycle, durable CAS | Approval conflict and security audit | Key rotation windows need operational discipline. |
| Malicious scenario input | Planner/state | Authenticated operator or poisoned source | Untrusted fields enter scenario | API/log/K8s/graph ingestion | Allow-list, strict Pydantic, prompt sanitizer, bounded context, supervisor | Scope findings/invalid-job events | Semantic poisoning may evade syntax checks; add provenance/review. |
| Arbitrary execution attempt | Host/infrastructure | Malicious input/operator | Input requests commands/apply | Agent/remediation/export | No shell/tool execution, Shadow scope, proposal-only exporters | Scope rejection/code review | Future adapters could expand risk; threat-model every new tool. |
| API abuse | Availability/data | Authenticated or network attacker | Endpoint reachable | FastAPI | Size/pagination limits, RBAC, rate-limit port, CORS, safe errors | 401/403/429 metrics and audit | Distributed enforcement/WAF are external. |
| Denial of service | Availability | Network/broker attacker | High request/job volume | API, broker, worker, graph | Edge limits contract, backpressure, bounded messages/retries/path depth | Readiness, latency, queue/worker metrics | Capacity targets/load environment are not yet established. |
| Result tampering | Evidence | DB/storage administrator | Artifact store write access | Result/checkpoint storage | Immutable publication, version binding, checkpoint hash/schema | Restore/integrity checks and audit | External immutable storage/signing is pending. |
| Audit tampering | Accountability | Privileged operator | Audit backend compromised | Audit sink/retention | Append-only typed port, durable capability, retention contract | SIEM sequence/retention monitoring | No concrete immutable SIEM adapter; external dependency. |
| Telemetry leakage | Metadata/secrets | Observer/backend compromise | Unsafe labels/payload exported | Metrics/traces/logs | Fixed schemas/vocabulary, no raw state, bounded correlation | Schema rejection and backend policy | IDs still reveal activity; restrict access and retention. |

## Trust boundaries

Production boundaries are TLS/API gateway, OIDC/JWKS, broker, server database, managed
secrets, distributed limiter, SIEM and telemetry. The repository validates capabilities
but does not claim any of those services are connected. New adapters require independent
authentication, authorization, timeout, redaction, retry, failure-injection and recovery
review before promotion.
