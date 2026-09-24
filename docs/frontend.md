# Command Center frontend

`frontend/` is a React + TypeScript + Vite interface for the Autonomous Red
Teaming simulator. It is an API-only client: it does not read SQLite, Neo4j,
LangGraph state, local backend files, or execute graph queries in the browser.

## Run locally

Start the API in one terminal with its development composition:

```powershell
$env:ART_ENV = "development"
python -m uvicorn art_sim.api.main:app --host 127.0.0.1 --port 8080
```

Then start the interface in another terminal:

```powershell
Set-Location frontend
npm ci
npm run dev
```

By default, Vite proxies `/api` and `/health` to `http://127.0.0.1:8080`.
This avoids adding a broad CORS policy to the API. Set `VITE_BACKEND_URL` to
change the development proxy target. In a deployed environment, use a same-origin
reverse proxy or configure an explicit allow-list at the API boundary.

`VITE_API_BASE_URL` is optional. Leave it empty for the local proxy; set it to
the same-origin API prefix when the frontend is served behind a reverse proxy.
`VITE_POLL_INTERVAL_MS` controls refreshes for active runs and is clamped to a
minimum of three seconds.

## Authentication and authorization

The sign-in boundary supplies the existing development bearer-token format:

```text
Authorization: Bearer development:<viewer|operator|admin>:<subject>
```

It is validated through `/api/v1/identity`, remains in React memory only, and is never written to local storage,
session storage, URLs, logs, or source control. This mechanism is development
only and the backend rejects it in production composition. `viewer` can inspect;
`operator` and `admin` can create a configured scenario and submit the existing
simulation-workflow approval decision.

Every application route is protected by `AuthProvider`. A 401 expires the in-memory
session; a 403 renders a permission-specific state without revealing backend details.
The shell displays the verified subject, roles and authentication strength and supports
audited logout. Production builds default to OIDC mode and accept a deployment-injected
`BrowserOidcAdapter` for Authorization Code with PKCE; no IdP client secret is bundled.
The admin-only Security view reads non-sensitive posture and typed events from the API.

## Data and safety model

The interface renders only values returned by the versioned FastAPI endpoints.
Dashboard metrics are explicitly scoped to the current bounded API page; no
global totals are inferred. Scenario choices come from `GET /api/v1/scenarios`.
Run creation uses the existing idempotency header. Detail polling covers `CREATED`,
`RUNNING`, `WAITING_APPROVAL`, and `RESUMING`, and stops automatically on every terminal
state or component unmount. Network and `429` failures use bounded backoff; `401` expires
the in-memory session and `403` stops polling with a permission state. Result endpoints
return `409` until `SUCCEEDED`; the UI shows **Not available yet**, never an empty or
fabricated attack path, blast radius, remediation, verification, or report.

Authorized operators receive a cancellation control only for active states. It requires
explicit confirmation and calls the cooperative backend endpoint; it cannot terminate a
process or execute infrastructure actions. `CANCELLED` is terminal and stops polling.
Admins with `audit:read` can view the API's safe lifecycle timeline. Worker owner IDs,
fencing internals, and raw audit metadata are not exposed to the browser.

Remediation surfaces are labelled **PROPOSED REMEDIATION · SIMULATION ONLY**.
The UI has no infrastructure action, apply, deploy, attack, exploit, Terraform,
OpenTofu, `kubectl`, AWS, or Kubernetes control. Approval is only the durable
HITL gate already provided by the API for the simulated workflow.

## Structure and validation

```text
frontend/src/
  api/          centralized typed HTTP boundary
  components/   reusable shell, states, table, cards and result panel
  pages/        dashboard, inventory, creation and run detail
  utils/        presentation-only formatting helpers
  test/         Vitest setup
```

```powershell
Set-Location frontend
npm run lint
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```

The CI workflow runs these checks in addition to backend Ruff, Mypy, pytest,
dependency audit, wheel build, and Gitleaks.
