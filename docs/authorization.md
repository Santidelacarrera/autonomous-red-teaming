# Authorization

The single source of truth is `security/permissions.py`.

| Role | Permissions |
| --- | --- |
| `viewer` | simulation/risk/attack-path/blast-radius/remediation/verification/report read |
| `operator` | viewer permissions plus simulation create, approve, and reject |
| `admin` | operator permissions plus simulation admin, audit read, security admin, and identity admin |

FastAPI dependencies call `authorize(identity, permission)` for every protected read and
write. Missing or invalid authentication returns 401. A verified identity without the
required permission returns 403. Frontend route and control visibility mirrors this
matrix but is not a security control.

Approval is treated as sensitive: a verified permission is required, optional MFA
step-up is evaluated only from the verified authenticator context, a subject-scoped rate limit is
applied, and the durable coordinator enforces waiting state plus compare-and-set. The
existing remediation workflow separately verifies HMAC-bound approval evidence and
rejects replay, duplicate decisions, invalid lifecycle, and forged state.

No identity administration CRUD or password/secret endpoint exists. Future administration
must use an injected external IdP administration adapter and explicit permissions.

## Organization isolation

Roles are enforced *inside* an organization. Every route that names a run first proves the run
belongs to the caller's organization (`SimulationService.get_scoped`); otherwise the answer is
**404**, identical to an unknown run, and an `authorization.denied` audit event is written.
This holds even for an administrator of another organization. Lists are filtered in the
database, and idempotency keys are namespaced per organization. See
`docs/security-controls.md` for the tests that prove each of these both ways.

## Review window

A run waiting for approval has a bounded review window (`approval_ttl`). The check runs in the
same transaction as the decision compare-and-set; an expired decision returns **410** and
changes nothing. Expiry never approves anything.

Client-provided headers or body fields do not participate in authorization or MFA. A
viewer remains unable to approve even when its verified identity has MFA assurance.
