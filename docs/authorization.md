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
step-up is evaluated from the authentication context, a subject-scoped rate limit is
applied, and the durable coordinator enforces waiting state plus compare-and-set. The
existing remediation workflow separately verifies HMAC-bound approval evidence and
rejects replay, duplicate decisions, invalid lifecycle, and forged state.

No identity administration CRUD or password/secret endpoint exists. Future administration
must use an injected external IdP administration adapter and explicit permissions.
