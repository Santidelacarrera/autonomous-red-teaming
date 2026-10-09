"""Access control by organization and role: positive and negative controls.

Tenant isolation is *complete mediation*: every route that names a run first proves the run
belongs to the caller's organization, and a foreign run is indistinguishable from a missing
one (404), so identifiers cannot be enumerated across tenants. Roles are then enforced inside
the organization. The organization comes only from the verified credential — never from a
header, query string or request body the caller controls.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationService,
)
from art_sim.domain.exceptions import AuthenticationError
from art_sim.platform.health import HealthService
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import InMemorySecurityAuditSink, SecurityEventType
from art_sim.security.providers.oidc import OidcIdentityProvider, OidcSettings

ACME_OP = {"Authorization": "Bearer development:operator:alice#acme"}
ACME_VIEWER = {"Authorization": "Bearer development:viewer:vera#acme"}
ACME_ADMIN = {"Authorization": "Bearer development:admin:ada#acme"}
GLOBEX_OP = {"Authorization": "Bearer development:operator:mallory#globex"}
GLOBEX_ADMIN = {"Authorization": "Bearer development:admin:gina#globex"}
APPROVE = {"decision": "approved", "reason": "Reviewed the simulated countermeasure evidence."}


async def _healthy() -> None:
    """Deterministic readiness dependency."""


class _Env:
    def __init__(self, client: TestClient, store: SqliteOperationalStore, audit: InMemorySecurityAuditSink):
        self.client, self.store, self.audit = client, store, audit

    def create(self, headers: dict[str, str], extra: dict[str, str] | None = None) -> UUID:
        response = self.client.post(
            "/api/v1/simulations",
            headers={**headers, **(extra or {})},
            json={"scenario_id": "shadow-demo"},
        )
        assert response.status_code == 202, response.text
        return UUID(response.json()["run_id"])

    async def park_waiting(self, run_id: UUID) -> None:
        claim = await self.store.acquire_execution(run_id, "iso-test", UUID(int=1))
        assert claim is not None
        await self.store.mark_waiting_approval(run_id, "iso-test", claim.fencing_token)


async def _env(tmp_path: Path) -> _Env:
    store = SqliteOperationalStore(tmp_path / "tenants.sqlite3")
    await store.initialize()
    audit = InMemorySecurityAuditSink()
    app = create_app(
        SimulationService(store, ScenarioCatalog(("shadow-demo",))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_audit=audit,
        cancellation_service=CancellationService(store),
    )
    return _Env(TestClient(app), store, audit)


# Every route that takes a run_id, with the method used to reach it.
RUN_ROUTES = [
    ("GET", "", None),
    ("POST", "/cancel", None),
    ("GET", "/events", None),
    ("POST", "/approval", APPROVE),
    ("GET", "/risk", None),
    ("GET", "/attack-paths", None),
    ("GET", "/blast-radius", None),
    ("GET", "/remediations", None),
    ("GET", "/review", None),
    ("GET", "/verification", None),
    ("GET", "/report", None),
]


# ------------------------------------------------------------------ tenant isolation


@pytest.mark.parametrize(("method", "suffix", "body"), RUN_ROUTES)
async def test_foreign_organization_cannot_reach_any_run_route(
    tmp_path: Path, method: str, suffix: str, body: dict[str, str] | None
) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    await env.park_waiting(run_id)
    before = await env.store.get_run(run_id)

    # globex-admin holds every permission, so only the organization boundary can stop it.
    response = env.client.request(
        method, f"/api/v1/simulations/{run_id}{suffix}", headers=GLOBEX_ADMIN, json=body
    )

    assert response.status_code == 404, f"{method} {suffix} leaked: {response.status_code}"
    assert response.json()["error"]["code"] == "RUN_NOT_FOUND"
    assert await env.store.get_run(run_id) == before  # no side effect from the foreign call


async def test_foreign_run_is_indistinguishable_from_a_missing_run(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    foreign = env.client.get(f"/api/v1/simulations/{run_id}", headers=GLOBEX_OP)
    missing = env.client.get(f"/api/v1/simulations/{uuid4()}", headers=GLOBEX_OP)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json()["error"]["code"] == missing.json()["error"]["code"]
    assert foreign.json()["error"]["message"] == missing.json()["error"]["message"]


async def test_owner_organization_still_has_full_access(tmp_path: Path) -> None:
    """Positive control: the boundary blocks strangers, not the owning organization."""
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    assert env.client.get(f"/api/v1/simulations/{run_id}", headers=ACME_VIEWER).status_code == 200
    assert env.client.get(f"/api/v1/simulations/{run_id}/events", headers=ACME_ADMIN).status_code == 200
    assert env.client.get(f"/api/v1/simulations/{run_id}/report", headers=ACME_OP).status_code == 409


async def test_listing_only_returns_the_callers_organization(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    mine = {env.create(ACME_OP) for _ in range(3)}
    theirs = {env.create(GLOBEX_OP) for _ in range(2)}

    acme = env.client.get("/api/v1/simulations", headers=ACME_VIEWER).json()["items"]
    globex = env.client.get("/api/v1/simulations", headers=GLOBEX_OP).json()["items"]

    assert {UUID(item["run_id"]) for item in acme} == mine
    assert {UUID(item["run_id"]) for item in globex} == theirs
    assert {item["organization_id"] for item in acme} == {"acme"}


async def test_pagination_does_not_mix_other_tenants_into_pages(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    for _ in range(5):
        env.create(ACME_OP)
        env.create(GLOBEX_OP)
    first = env.client.get("/api/v1/simulations?limit=3&offset=0", headers=ACME_OP).json()["items"]
    second = env.client.get("/api/v1/simulations?limit=3&offset=3", headers=ACME_OP).json()["items"]
    assert len(first) == 3
    assert len(second) == 2
    assert {item["organization_id"] for item in first + second} == {"acme"}


async def test_status_filter_and_tenant_filter_compose(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    waiting = env.create(ACME_OP)
    await env.park_waiting(waiting)
    env.create(ACME_OP)
    other = env.create(GLOBEX_OP)
    await env.park_waiting(other)
    items = env.client.get("/api/v1/simulations?status=waiting_approval", headers=ACME_OP).json()["items"]
    assert [UUID(i["run_id"]) for i in items] == [waiting]


async def test_idempotency_keys_are_not_shared_between_organizations(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    key = {"Idempotency-Key": "shared-client-key-0001"}
    acme_first = env.create(ACME_OP, key)
    acme_retry = env.create(ACME_OP, key)
    globex = env.create(GLOBEX_OP, key)
    assert acme_first == acme_retry  # idempotency still works inside one organization
    assert globex != acme_first  # ...and never hands tenant A's run to tenant B
    assert (await env.store.get_run(globex)).organization_id == "globex"


async def test_organization_is_taken_from_the_credential_not_from_request_data(
    tmp_path: Path,
) -> None:
    env = await _env(tmp_path)
    spoofed = env.client.post(
        "/api/v1/simulations?organization_id=acme",
        headers={**GLOBEX_OP, "X-Organization": "acme", "X-Organization-Id": "acme"},
        json={"scenario_id": "shadow-demo"},
    )
    assert spoofed.status_code == 202
    assert spoofed.json()["organization_id"] == "globex"
    body_spoof = env.client.post(
        "/api/v1/simulations",
        headers=GLOBEX_OP,
        json={"scenario_id": "shadow-demo", "organization_id": "acme"},
    )
    assert body_spoof.status_code == 422  # extra="forbid": the field is not even accepted


async def test_cross_organization_probe_is_audited_as_a_denial(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    env.client.get(f"/api/v1/simulations/{run_id}", headers=GLOBEX_OP)
    denied = [
        event
        for event in await env.audit.recent(limit=200)
        if event.event_type is SecurityEventType.AUTHORIZATION_DENIED
    ]
    assert len(denied) == 1
    assert denied[0].subject == "mallory"
    assert denied[0].run_id == run_id
    assert denied[0].result == "denied"


async def test_unknown_run_ids_are_not_recorded_as_cross_organization_denials(
    tmp_path: Path,
) -> None:
    """A mistyped identifier is an ordinary 404; only a real tenant-boundary probe is a denial."""
    env = await _env(tmp_path)
    for _ in range(3):
        assert env.client.get(f"/api/v1/simulations/{uuid4()}", headers=GLOBEX_OP).status_code == 404
    denied = [
        event
        for event in await env.audit.recent(limit=200)
        if event.event_type is SecurityEventType.AUTHORIZATION_DENIED
    ]
    assert denied == []


@pytest.mark.parametrize("key", ["short", "x" * 129, ""])
async def test_idempotency_keys_keep_their_length_bounds_under_namespacing(
    tmp_path: Path, key: str
) -> None:
    """Hashing the key per organization must not let malformed client keys through."""
    env = await _env(tmp_path)
    response = env.client.post(
        "/api/v1/simulations",
        headers={**ACME_OP, "Idempotency-Key": key},
        json={"scenario_id": "shadow-demo"},
    )
    assert response.status_code == 422
    assert await env.store.list_runs(organization_id="acme") == ()


async def test_foreign_organization_cannot_decide_and_owner_still_can(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    await env.park_waiting(run_id)
    url = f"/api/v1/simulations/{run_id}/approval"
    assert env.client.post(url, headers=GLOBEX_ADMIN, json=APPROVE).status_code == 404
    assert (await env.store.get_run(run_id)).approval_actor is None
    assert env.client.post(url, headers=ACME_OP, json=APPROVE).status_code == 200


def test_invalid_organization_ids_are_rejected_by_the_development_provider() -> None:
    import asyncio

    provider = DevelopmentHeaderAuthenticator(enabled=True)
    for bad in ("development:operator:alice#", "development:operator:alice#../etc", "development:operator:a#" + "x" * 65):
        # An empty suffix means "default organization"; anything else must match the pattern.
        if bad.endswith("#"):
            identity = asyncio.run(provider.validate_token(bad))
            assert identity.organization_id == "default"
            continue
        with pytest.raises(AuthenticationError):
            asyncio.run(provider.validate_token(bad))


# ------------------------------------------------------------------- role matrix


@pytest.mark.parametrize(
    ("headers", "expected"),
    [(ACME_VIEWER, 403), (ACME_OP, 202), (ACME_ADMIN, 202)],
    ids=["viewer", "operator", "admin"],
)
async def test_only_operators_and_admins_can_create(
    tmp_path: Path, headers: dict[str, str], expected: int
) -> None:
    env = await _env(tmp_path)
    response = env.client.post("/api/v1/simulations", headers=headers, json={"scenario_id": "shadow-demo"})
    assert response.status_code == expected


@pytest.mark.parametrize(
    ("headers", "expected"),
    [(ACME_VIEWER, 403), (ACME_OP, 200), (ACME_ADMIN, 200)],
    ids=["viewer", "operator", "admin"],
)
async def test_only_operators_and_admins_can_approve_inside_their_organization(
    tmp_path: Path, headers: dict[str, str], expected: int
) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    await env.park_waiting(run_id)
    response = env.client.post(f"/api/v1/simulations/{run_id}/approval", headers=headers, json=APPROVE)
    assert response.status_code == expected


@pytest.mark.parametrize(
    ("headers", "expected"),
    [(ACME_VIEWER, 403), (ACME_OP, 403), (ACME_ADMIN, 200)],
    ids=["viewer", "operator", "admin"],
)
async def test_audit_trail_and_security_status_are_admin_only(
    tmp_path: Path, headers: dict[str, str], expected: int
) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    assert env.client.get(f"/api/v1/simulations/{run_id}/events", headers=headers).status_code == expected
    assert env.client.get("/api/v1/security/status", headers=headers).status_code == expected


@pytest.mark.parametrize("suffix", ["", "/risk", "/attack-paths", "/report", "/review"])
async def test_viewers_can_read_but_never_mutate(tmp_path: Path, suffix: str) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    read = env.client.get(f"/api/v1/simulations/{run_id}{suffix}", headers=ACME_VIEWER)
    assert read.status_code in {200, 409}  # 409 = authorized, result not produced yet
    assert env.client.post(f"/api/v1/simulations/{run_id}/cancel", headers=ACME_VIEWER).status_code == 403


async def test_role_check_precedes_tenant_check_so_viewers_learn_nothing(tmp_path: Path) -> None:
    env = await _env(tmp_path)
    run_id = env.create(ACME_OP)
    viewer_other_org = {"Authorization": "Bearer development:viewer:eve#globex"}
    assert env.client.post(f"/api/v1/simulations/{run_id}/cancel", headers=viewer_other_org).status_code == 403


# ------------------------------------------------------------- OIDC organization claim


class _Issuer:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk["kid"] = "k1"
        self.jwks = {"keys": [jwk]}
        self.url = "https://identity.example.com"

    def token(self, **overrides: Any) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.url, "aud": "art-sim", "sub": "u1", "iat": now,
            "nbf": now - timedelta(seconds=1), "exp": now + timedelta(minutes=5),
            "roles": ["operator"], "org_id": "acme",
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def provider(self, **settings: Any) -> OidcIdentityProvider:
        async def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=self.jwks)

        return OidcIdentityProvider(
            OidcSettings(
                issuer=self.url, audience="art-sim", jwks_url=f"{self.url}/jwks.json", **settings
            ),
            httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )


async def test_oidc_organization_comes_from_the_verified_claim() -> None:
    issuer = _Issuer()
    identity = await issuer.provider().validate_token(issuer.token(org_id="globex"))
    assert identity.organization_id == "globex"


async def test_oidc_token_without_an_organization_claim_is_rejected() -> None:
    issuer = _Issuer()
    with pytest.raises(AuthenticationError):
        await issuer.provider().validate_token(issuer.token(org_id=None))


@pytest.mark.parametrize("bad", ["", "../acme", "acme corp", "a" * 65, 7, ["acme"], {"id": "acme"}])
async def test_oidc_rejects_malformed_organization_claims(bad: object) -> None:
    issuer = _Issuer()
    with pytest.raises(AuthenticationError):
        await issuer.provider().validate_token(issuer.token(org_id=bad))


async def test_single_tenant_fallback_is_an_explicit_operator_choice() -> None:
    issuer = _Issuer()
    provider = issuer.provider(default_organization_id="solo")
    assert (await provider.validate_token(issuer.token(org_id=None))).organization_id == "solo"
    # An explicit claim still wins over the configured fallback.
    assert (await provider.validate_token(issuer.token(org_id="acme"))).organization_id == "acme"


async def test_custom_organization_claim_name_is_honored() -> None:
    issuer = _Issuer()
    provider = issuer.provider(organization_claim="tenant")
    assert (await provider.validate_token(issuer.token(tenant="initech", org_id="acme"))).organization_id == "initech"
    with pytest.raises(AuthenticationError):
        await provider.validate_token(issuer.token(org_id="acme"))  # default claim name is ignored
