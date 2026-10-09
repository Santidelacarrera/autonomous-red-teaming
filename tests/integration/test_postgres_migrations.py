"""Integration tests for the Alembic migration chain against a real PostgreSQL.

Requires a reachable PostgreSQL (set ART_PG_TEST_DSN, or run the default dev container at
postgresql://postgres:devpw@127.0.0.1:55432/artsim) whose role may create databases. Skipped
if no database is reachable. Each test runs against its own throwaway *database* (not just
a schema), created and dropped per test, so it never collides with
``tests/integration/test_postgres_store.py``'s fixtures running in the same server.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from alembic import command
from alembic.config import Config

DSN = os.getenv("ART_PG_TEST_DSN", "postgresql://postgres:devpw@127.0.0.1:55432/artsim")
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# alembic's `env.py` drives the async engine with its own `asyncio.run(...)`; calling
# `command.upgrade`/`downgrade` directly from inside a pytest-asyncio test would nest event
# loops, so every call below runs on a worker thread, which has none.


async def _upgrade(config: Config, revision: str) -> None:
    await asyncio.to_thread(command.upgrade, config, revision)


async def _downgrade(config: Config, revision: str) -> None:
    await asyncio.to_thread(command.downgrade, config, revision)


def _dsn_with_database(dsn: str, database: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


async def _reachable() -> bool:
    try:
        conn = await asyncpg.connect(DSN, timeout=3)
    except (OSError, asyncpg.PostgresError):
        return False
    await conn.close()
    return True


@pytest.fixture
async def migration_dsn() -> AsyncGenerator[str]:
    """Create a uniquely named throwaway database and drop it afterward."""
    if not await _reachable():
        pytest.skip("No PostgreSQL reachable for integration tests")
    database = f"art_migrations_test_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(DSN)
    try:
        await admin.execute(f'CREATE DATABASE "{database}"')
    finally:
        await admin.close()
    try:
        yield _dsn_with_database(DSN, database)
    finally:
        admin = await asyncpg.connect(DSN)
        try:
            await admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid != pg_backend_pid()",
                database,
            )
            await admin.execute(f'DROP DATABASE IF EXISTS "{database}"')
        finally:
            await admin.close()


def _config_for(dsn: str) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", dsn)
    return config


async def test_upgrade_head_creates_expected_tables(migration_dsn: str) -> None:
    config = _config_for(migration_dsn)
    await _upgrade(config, "head")

    conn = await asyncpg.connect(migration_dsn)
    try:
        tables = {
            row["table_name"]
            for row in await conn.fetch(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            )
        }
    finally:
        await conn.close()
    assert {
        "simulation_runs",
        "workflow_checkpoints",
        "audit_events",
        "api_idempotency",
        "worker_leases",
        "simulation_results",
        "simulation_reviews",
        "alembic_version",
    } <= tables


async def test_upgrade_head_creates_retention_indexes(migration_dsn: str) -> None:
    config = _config_for(migration_dsn)
    await _upgrade(config, "head")

    conn = await asyncpg.connect(migration_dsn)
    try:
        indexes = {
            row["indexname"]
            for row in await conn.fetch(
                "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
            )
        }
    finally:
        await conn.close()
    assert "ix_simulation_runs_status_updated_at" in indexes
    assert "ix_simulation_results_created_at" in indexes
    assert "ix_workflow_checkpoints_created_at" in indexes


async def test_downgrade_to_base_drops_tables(migration_dsn: str) -> None:
    config = _config_for(migration_dsn)
    await _upgrade(config, "head")
    await _downgrade(config, "base")

    conn = await asyncpg.connect(migration_dsn)
    try:
        remaining = await conn.fetch(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name != 'alembic_version'"
        )
    finally:
        await conn.close()
    assert remaining == []


async def test_upgrade_is_idempotent_against_an_already_initialized_database(
    migration_dsn: str,
) -> None:
    """Running 0001 against a DB already bootstrapped by ``store.initialize()`` is a no-op."""
    conn = await asyncpg.connect(migration_dsn)
    try:
        await conn.execute(
            'CREATE TABLE "simulation_runs" ('
            "  run_id UUID PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL,"
            "  approval_status TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL"
            ")"
        )
    finally:
        await conn.close()

    config = _config_for(migration_dsn)
    await _upgrade(config, "head")  # must not raise on the pre-existing table

    conn = await asyncpg.connect(migration_dsn)
    try:
        version = await conn.fetchval("SELECT version_num FROM alembic_version")
    finally:
        await conn.close()
    assert version == "0002"
