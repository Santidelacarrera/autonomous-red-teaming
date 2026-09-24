"""Identity, JWT, RBAC, rate limit, CORS, headers, and audit regressions."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from art_sim.api.app import create_app
from art_sim.api.services import ApprovalService, ScenarioCatalog, SimulationService
from art_sim.domain.exceptions import AuthenticationError, AuthorizationError, ConfigurationError
from art_sim.platform.config import RuntimeEnvironment
from art_sim.platform.health import HealthService
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import InMemorySecurityAuditSink, SecurityEventType
from art_sim.security.config import AuthenticationProviderKind, SecuritySettings
from art_sim.security.permissions import Permission, authorize
from art_sim.security.providers.development import DevelopmentHeaderAuthenticator
from art_sim.security.providers.oidc import OidcIdentityProvider, OidcSettings
from art_sim.security.rate_limit import InMemoryRateLimiter, RateLimitPolicy


async def _healthy() -> None:
    """Deterministic readiness probe."""


async def _secured_client(
    tmp_path: Path,
    *,
    settings: SecuritySettings | None = None,
) -> tuple[TestClient, InMemorySecurityAuditSink]:
    store = SqliteOperationalStore(tmp_path / "security.sqlite3")
    await store.initialize()
    audit = InMemorySecurityAuditSink()
    app = create_app(
        SimulationService(store, ScenarioCatalog(("shadow-demo",))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_settings=settings or SecuritySettings(),
        rate_limiter=InMemoryRateLimiter(),
        security_audit=audit,
    )
    return TestClient(app), audit


async def test_development_identity_derives_permissions_from_central_policy() -> None:
    provider = DevelopmentHeaderAuthenticator(enabled=True)
    viewer = await provider.authenticate("Bearer development:viewer:alice")
    assert Permission.SIMULATION_READ.value in viewer.permissions
    assert Permission.SIMULATION_CREATE.value not in viewer.permissions
    with pytest.raises(AuthorizationError):
        authorize(viewer, Permission.SIMULATION_CREATE)
    with pytest.raises(AuthenticationError):
        await provider.authenticate("Bearer malformed")
    with pytest.raises(ConfigurationError):
        DevelopmentHeaderAuthenticator(enabled=False)


def test_non_development_security_configuration_fails_closed() -> None:
    with pytest.raises(ValueError, match="OIDC"):
        SecuritySettings(environment=RuntimeEnvironment.PRODUCTION)
    with pytest.raises(ValueError, match="CORS"):
        SecuritySettings(cors_allowed_origins=("*",))
    with pytest.raises(ValueError, match="allow-list"):
        SecuritySettings(
            environment=RuntimeEnvironment.PRODUCTION,
            authentication_provider=AuthenticationProviderKind.OIDC,
            oidc=OidcSettings(
                issuer="https://identity.example.com",
                audience="art-sim",
                jwks_url="https://identity.example.com/.well-known/jwks.json",
            ),
        )


async def test_production_composition_rejects_development_authenticator(tmp_path: Path) -> None:
    store = SqliteOperationalStore(tmp_path / "production.sqlite3")
    settings = SecuritySettings(
        environment=RuntimeEnvironment.PRODUCTION,
        authentication_provider=AuthenticationProviderKind.OIDC,
        oidc=OidcSettings(
            issuer="https://identity.example.com",
            audience="art-sim",
            jwks_url="https://identity.example.com/.well-known/jwks.json",
        ),
        cors_allowed_origins=("https://command.example.com",),
        hsts_enabled=True,
    )
    with pytest.raises(ConfigurationError, match="adapter"):
        create_app(
            SimulationService(store, ScenarioCatalog(("shadow-demo",))),
            ApprovalService(store),
            HealthService({"store": _healthy}),
            DevelopmentHeaderAuthenticator(enabled=True),
            security_settings=settings,
            rate_limiter=InMemoryRateLimiter(),
            security_audit=InMemorySecurityAuditSink(),
        )


async def test_rate_limiter_isolates_keys_and_returns_retry_delay() -> None:
    limiter = InMemoryRateLimiter()
    policy = RateLimitPolicy("test", requests=1)
    assert (await limiter.consume("alice", policy)).allowed
    limited = await limiter.consume("alice", policy)
    assert not limited.allowed
    assert limited.retry_after_seconds >= 1
    assert (await limiter.consume("bob", policy)).allowed


async def test_api_enforces_permissions_rate_limits_headers_cors_and_audit(tmp_path: Path) -> None:
    settings = SecuritySettings(
        cors_allowed_origins=("https://command.example.com",),
        simulation_creates_per_minute=1,
    )
    client, audit = await _secured_client(tmp_path, settings=settings)
    viewer = {"Authorization": "Bearer development:viewer:viewer-user"}
    operator = {"Authorization": "Bearer development:operator:operator-user"}

    anonymous = client.get("/api/v1/simulations")
    assert anonymous.status_code == 401
    denied = client.post("/api/v1/simulations", headers=viewer, json={"scenario_id": "shadow-demo"})
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "FORBIDDEN"

    first = client.post("/api/v1/simulations", headers=operator, json={"scenario_id": "shadow-demo"})
    second = client.post("/api/v1/simulations", headers=operator, json={"scenario_id": "shadow-demo"})
    assert first.status_code == 202
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) >= 1

    health = client.get("/health")
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    assert health.headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert health.headers["Referrer-Policy"] == "no-referrer"
    assert "Strict-Transport-Security" not in health.headers

    accepted = client.options(
        "/api/v1/simulations",
        headers={
            "Origin": "https://command.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    rejected = client.options(
        "/api/v1/simulations",
        headers={"Origin": "https://unknown.example.com", "Access-Control-Request-Method": "GET"},
    )
    assert accepted.status_code == 200
    assert accepted.headers["Access-Control-Allow-Origin"] == "https://command.example.com"
    assert rejected.status_code == 400

    events = await audit.recent(50)
    types = {event.event_type for event in events}
    assert SecurityEventType.AUTHENTICATION_FAILURE in types
    assert SecurityEventType.AUTHORIZATION_DENIED in types
    assert SecurityEventType.SIMULATION_CREATED in types
    assert SecurityEventType.RATE_LIMIT_EXCEEDED in types
    serialized = "".join(event.model_dump_json() for event in events)
    assert "Bearer development" not in serialized
    assert "Authorization" not in serialized


async def test_security_status_is_admin_only(tmp_path: Path) -> None:
    client, _ = await _secured_client(tmp_path)
    operator = {"Authorization": "Bearer development:operator:alice"}
    admin = {"Authorization": "Bearer development:admin:security-admin"}
    assert client.get("/api/v1/security/status", headers=operator).status_code == 403
    response = client.get("/api/v1/security/status", headers=admin)
    assert response.status_code == 200
    assert response.json()["authentication_provider"] == "development"
    assert "jwks" not in response.text.lower()


async def test_mfa_policy_denies_standard_development_identity(tmp_path: Path) -> None:
    client, _ = await _secured_client(
        tmp_path,
        settings=SecuritySettings(mfa_required_for_sensitive_actions=True),
    )
    operator = {"Authorization": "Bearer development:operator:alice"}
    created = client.post("/api/v1/simulations", headers=operator, json={"scenario_id": "shadow-demo"})
    response = client.post(
        f"/api/v1/simulations/{created.json()['run_id']}/approval",
        headers=operator,
        json={"decision": "approved"},
    )
    assert response.status_code == 403


class _OidcFixture:
    def __init__(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        public_jwk["kid"] = "current-key"
        self.jwks = {"keys": [public_jwk]}
        self.issuer = "https://identity.example.com"
        self.audience = "art-sim"

    def token(self, **overrides: Any) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "oidc-user",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "roles": ["operator"],
            "amr": ["pwd", "mfa"],
            "jti": "token-id",
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "current-key"})

    def provider(self) -> OidcIdentityProvider:
        async def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=self.jwks)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return OidcIdentityProvider(
            OidcSettings(
                issuer=self.issuer,
                audience=self.audience,
                jwks_url=f"{self.issuer}/.well-known/jwks.json",
            ),
            client,
        )


async def test_oidc_validates_signature_claims_roles_and_mfa() -> None:
    fixture = _OidcFixture()
    identity = await fixture.provider().validate_token(fixture.token())
    assert identity.subject == "oidc-user"
    assert identity.authentication.mfa_satisfied
    assert Permission.SIMULATION_CREATE.value in identity.permissions


@pytest.mark.parametrize(
    "override",
    [
        {"iss": "https://attacker.example.com"},
        {"aud": "another-api"},
        {"exp": datetime.now(UTC) - timedelta(minutes=5)},
    ],
)
async def test_oidc_rejects_invalid_issuer_audience_and_expiration(override: dict[str, Any]) -> None:
    fixture = _OidcFixture()
    with pytest.raises(AuthenticationError):
        await fixture.provider().validate_token(fixture.token(**override))


async def test_oidc_rejects_invalid_signature_unknown_kid_and_none_algorithm() -> None:
    fixture = _OidcFixture()
    provider = fixture.provider()
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    claims = {
        "iss": fixture.issuer,
        "aud": fixture.audience,
        "sub": "attacker",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "roles": ["admin"],
    }
    forged = jwt.encode(claims, attacker, algorithm="RS256", headers={"kid": "current-key"})
    unknown = jwt.encode(claims, fixture.private_key, algorithm="RS256", headers={"kid": "unknown-key"})
    unsecured = jwt.encode(claims, key="", algorithm="none", headers={"kid": "current-key"})
    for token in (forged, unknown, unsecured):
        with pytest.raises(AuthenticationError):
            await provider.validate_token(token)
