# Test matrix

The repository contains unit tests plus a manually invoked Shadow E2E script. There is
no isolated integration-test suite or coverage tool configured; cells marked `-` are not
claims of absent behavior, only absent automated test tier coverage.

| Area | Unit | Integration | E2E |
| --- | --- | --- | --- |
| Domain validation / CVSS | yes | - | - |
| Cypher validator | yes | - | - |
| Neo4j shortest path | - | - | manual Shadow read |
| Attack LangGraph | yes | - | manual Shadow read |
| Shadow graph | yes | - | - |
| Risk / blast radius | yes | - | - |
| HITL / HMAC / lifecycle | yes | - | - |
| Operational store / checkpoint | yes | file-backed restart test | - |
| Durable audit / approval CAS | yes | file-backed concurrent-worker test | - |
| Identity / RBAC / JWT / JWKS | yes | dedicated security suite with signed test keys | Real IdP tenant integration is deployment-owned. |
| Rate limiting / CORS / headers | yes | direct FastAPI tests | Distributed limiter and HTTPS edge require deployment adapters. |
| Frontend authentication | yes | protected state, login/logout and API error tests | Production PKCE adapter is injected by deployment. |
| Configuration / health / logging sink | yes | - | - |
| Verification | yes | - | - |
| Exporters | yes | - | - |
| Reporting / telemetry | yes | - | - |
| GitHub REST adapter | fake-client unit test | - | - |

`pytest-cov` is not installed or configured. Coverage percentage is deliberately not
reported; critical security paths have targeted regression tests.
