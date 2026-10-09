"""Alembic async migration environment for the PostgreSQL operational store.

This project does not use a SQLAlchemy ORM layer (``PostgresOperationalStore`` talks to
``asyncpg`` directly), so there is no ``target_metadata`` to autogenerate from. Every
migration is a hand-written, reviewed SQL change under ``migrations/versions/``; Alembic is
used purely for its versioned-migration ledger (``alembic_version``), ordering, and
upgrade/downgrade execution — the same schema `_SCHEMA` constant in
``art_sim.adapters.postgres_store`` documents, now evolved through tracked revisions instead
of only an idempotent ``CREATE TABLE IF NOT EXISTS`` baseline.

The DSN is never hard-coded: it is resolved at runtime from ``ART_DATABASE_DSN`` (set by
``scripts/run_migrations.py`` after reading it from the configured secret provider) or, for
local development and CI, from ``ART_PG_TEST_DSN``.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

config = context.config

if config.config_file_name is not None:
    # Keep the host process's loggers: the default (disable_existing_loggers=True) would silence
    # every logger created before migrations ran, including application and library loggers.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = None


def _resolve_dsn() -> str:
    # An explicitly configured sqlalchemy.url (e.g. set programmatically by a test against
    # its own throwaway database) always wins over the environment.
    configured = config.get_main_option("sqlalchemy.url")
    dsn = configured or os.environ.get("ART_DATABASE_DSN") or os.environ.get("ART_PG_TEST_DSN")
    if not dsn:
        raise RuntimeError(
            "ART_DATABASE_DSN (or ART_PG_TEST_DSN for local/CI) must be set to run migrations"
        )
    # asyncpg needs the SQLAlchemy async driver prefix; accept a plain postgresql:// DSN too.
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+asyncpg://" + dsn[len("postgresql://") :]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+asyncpg://" + dsn[len("postgres://") :]
    return dsn


def run_migrations_offline() -> None:
    """Emit SQL without a live connection (``alembic upgrade head --sql``)."""
    context.configure(
        url=_resolve_dsn(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live database using an async engine."""
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _resolve_dsn()
    connectable = async_engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
