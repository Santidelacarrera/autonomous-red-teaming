"""Production composition-root tests: fail-closed without config, and a real startup against
a live PostgreSQL + mounted secrets (other dependencies are only contacted at /readiness)."""

from __future__ import annotations

import os
from pathlib import Path

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient

from art_sim.api.compose import build_production_app
from art_sim.domain.exceptions import ConfigurationError

PG_DSN = os.getenv("ART_PG_TEST_DSN", "postgresql://postgres:devpw@127.0.0.1:55432/artsim")

_PROD_ENV = {
    "ART_ENV": "production",
    "ART_AUTH_MODE": "oidc",
    "ART_OIDC_ISSUER": "https://identity.example.com",
    "ART_OIDC_AUDIENCE": "art-sim",
    "ART_OIDC_JWKS_URL": "https://identity.example.com/.well-known/jwks.json",
    "ART_CORS_ALLOWED_ORIGINS": "https://command.example.com",
    "ART_HSTS_ENABLED": "true",
    "ART_RATE_LIMIT_ENABLED": "true",
    "ART_MFA_REQUIRED_FOR_SENSITIVE_ACTIONS": "false",
    "ART_BROKER_PROVIDER": "redis_streams",
    "ART_BROKER_ENDPOINT": "rediss://broker.example.com",
    "ART_BROKER_QUEUE": "art-sim",
    "ART_BROKER_CREDENTIAL_SECRET_NAME": "ART_BROKER_CREDENTIAL",
    "ART_DATABASE_PROVIDER": "postgresql",
    "ART_DATABASE_DSN_SECRET_NAME": "ART_DATABASE_DSN",
    "ART_SECRET_PROVIDER": "aws_secrets_manager",
    "ART_APPROVAL_SECRET_NAME": "ART_SIM_APPROVAL_SECRET",
    "ART_AUDIT_PROVIDER": "siem",
    "ART_AUDIT_RETENTION_DAYS": "365",
    "ART_TELEMETRY_PROVIDER": "otlp",
    "ART_RATE_LIMIT_PROVIDER": "redis",
    "ART_SIMULATION_RETENTION_DAYS": "90",
    "ART_RESULT_RETENTION_DAYS": "90",
    "ART_CHECKPOINT_RETENTION_DAYS": "30",
    "ART_DEAD_LETTER_RETENTION_DAYS": "30",
    "ART_TELEMETRY_RETENTION_DAYS": "30",
    "ART_TLS_TERMINATED_UPSTREAM": "true",
    "ART_TRUSTED_PROXY_HOPS": "1",
    "ART_RATE_LIMIT_ENDPOINT": "redis://127.0.0.1:65500/0",
    "ART_OTLP_ENDPOINT": "http://127.0.0.1:65501",
}


def _apply_env(monkeypatch: pytest.MonkeyPatch, secrets_dir: Path, audit_path: Path) -> None:
    for key, value in _PROD_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("ART_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv("ART_AUDIT_PATH", str(audit_path))


def _write_secrets(secrets_dir: Path) -> None:
    secrets_dir.mkdir(parents=True, exist_ok=True)
    (secrets_dir / "ART_SIM_APPROVAL_SECRET").write_text("x" * 48, encoding="utf-8")
    (secrets_dir / "ART_DATABASE_DSN").write_text(PG_DSN, encoding="utf-8")
    (secrets_dir / "ART_BROKER_CREDENTIAL").write_text("rediss://127.0.0.1:65502/0", encoding="utf-8")


async def test_composition_fails_closed_without_oidc(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _apply_env(monkeypatch, tmp_path / "secrets", tmp_path / "audit.jsonl")
    monkeypatch.delenv("ART_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("ART_OIDC_JWKS_URL", raising=False)
    with pytest.raises(ConfigurationError):
        await build_production_app()


async def test_composition_fails_closed_without_tls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _apply_env(monkeypatch, tmp_path / "secrets", tmp_path / "audit.jsonl")
    monkeypatch.setenv("ART_TLS_TERMINATED_UPSTREAM", "false")
    with pytest.raises(ConfigurationError):
        await build_production_app()


async def _pg_reachable() -> bool:
    try:
        conn = await asyncpg.connect(PG_DSN, timeout=3)
    except (OSError, asyncpg.PostgresError):
        return False
    await conn.close()
    return True


async def test_production_app_starts_and_serves_health(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    if not await _pg_reachable():
        pytest.skip("No PostgreSQL reachable for the production composition test")
    secrets_dir = tmp_path / "secrets"
    _write_secrets(secrets_dir)
    _apply_env(monkeypatch, secrets_dir, tmp_path / "audit" / "security.jsonl")

    app = await build_production_app()
    # The full composition passed every create_production_app capability check.
    assert app.title == "Autonomous Red Teaming Simulator API"
    # Startup runs the production lifespan (approval-secret resolution + store.initialize).
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            health = await client.get("/health")
            assert health.status_code == 200
            # Unauthenticated access to a protected route is rejected: 401 if the limiter is
            # reachable, or 503 fail-closed because the per-caller rate limiter runs first and
            # its Redis backend is intentionally unreachable in this test.
            denied = await client.get("/api/v1/scenarios")
            assert denied.status_code in (401, 503)
            # Hardened security headers are present on production responses.
            assert health.headers["Strict-Transport-Security"].startswith("max-age=")
