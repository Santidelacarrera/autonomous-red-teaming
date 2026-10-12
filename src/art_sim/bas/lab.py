"""Synthetic two-tenant lab: the only target the BAS framework can attack.

Safety by construction:

* HTTP goes through ``httpx.ASGITransport`` — the application is called in process; there is
  no socket, no DNS, no way to aim an attack at a remote host;
* data is synthetic (two fictional tenants, one run each) in a throw-away store;
* PostgreSQL is optional and **loopback only** (``require_loopback_dsn``).
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import httpx
from fastapi import FastAPI

from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationService,
)
from art_sim.platform.health import HealthService
from art_sim.platform.ports import OperationalStore
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import InMemorySecurityAuditSink, SecurityAuditEvent

SCENARIO = "shadow-demo"
TENANTS = ("acme", "globex")
_DENIAL_RESULTS = frozenset({"denied", "failed", "limited"})


class UnsafeTargetError(RuntimeError):
    """The requested target is outside the lab's safety envelope."""


def require_loopback_dsn(dsn: str) -> None:
    """Refuse any PostgreSQL host that is not the local machine."""
    host = urlparse(dsn).hostname or ""
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise UnsafeTargetError(f"BAS only attacks loopback databases; refusing host {host!r}")


def bearer(role: str, subject: str, tenant: str) -> dict[str, str]:
    """Development credential for ``subject`` with ``role`` inside ``tenant``."""
    return {"Authorization": f"Bearer development:{role}:{subject}#{tenant}"}


async def _healthy() -> None:
    """Deterministic readiness dependency."""


class RecordingAuditSink(InMemorySecurityAuditSink):
    """Keeps every event of the campaign so detection can be measured per attack."""

    def __init__(self) -> None:
        super().__init__(capacity=100_000)
        self.all: list[SecurityAuditEvent] = []

    async def append(self, event: SecurityAuditEvent) -> None:
        self.all.append(event)
        await super().append(event)


@dataclass
class Lab:
    """Handles the attack cases use; also tracks what the platform logged."""

    client: httpx.AsyncClient
    store: OperationalStore
    audit: RecordingAuditSink
    backend: str
    pg_pool: Any = None  # asyncpg pool of the PostgreSQL store, for data-layer attacks only
    victim_runs: dict[str, UUID] = field(default_factory=dict)
    last_request_id: str | None = None
    attacker: str | None = None
    victim: str | None = None

    async def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: object | None = None,
        content: bytes | None = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send one request through the in-process transport and remember its request id."""
        response = await self.client.request(
            method, path, headers=headers, json=json, content=content, params=params
        )
        self.last_request_id = response.headers.get("X-Request-ID")
        return response

    def audit_mark(self) -> int:
        """Position in the platform's own security audit stream."""
        return len(self.audit.all)

    def denials_since(self, mark: int) -> int:
        """Platform audit events of denial/failure kind appended after ``mark``."""
        return sum(1 for event in self.audit.all[mark:] if event.result in _DENIAL_RESULTS)


async def _seed(lab: Lab) -> None:
    """One run per tenant, parked in ``WAITING_APPROVAL`` so approval attacks are meaningful."""
    for tenant in TENANTS:
        response = await lab.client.post(
            "/api/v1/simulations",
            headers=bearer("operator", f"seed-{tenant}", tenant),
            json={"scenario_id": SCENARIO},
        )
        if response.status_code != 202:
            raise RuntimeError(f"lab seeding failed for {tenant}: {response.status_code}")
        run_id = UUID(response.json()["run_id"])
        claim = await lab.store.acquire_execution(run_id, "bas-seed", UUID(int=1))
        if claim is None:
            raise RuntimeError("lab seeding could not lease the run")
        await lab.store.mark_waiting_approval(run_id, "bas-seed", claim.fencing_token)
        lab.victim_runs[tenant] = run_id


AppFactory = Callable[[OperationalStore, RecordingAuditSink], FastAPI]


def default_app(store: OperationalStore, audit: RecordingAuditSink) -> FastAPI:
    """The real application, composed exactly as the API tests compose it."""
    return create_app(
        SimulationService(store, ScenarioCatalog((SCENARIO,))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_audit=audit,
        cancellation_service=CancellationService(store),
    )


@asynccontextmanager
async def open_lab(
    workdir: Path,
    *,
    postgres_dsn: str | None = None,
    app_factory: AppFactory = default_app,
) -> AsyncIterator[Lab]:
    """Build the lab, seed both tenants, and tear everything down afterwards."""
    store: OperationalStore
    pool_store = None
    if postgres_dsn is not None:
        require_loopback_dsn(postgres_dsn)
        from art_sim.adapters.postgres_store import PostgresOperationalStore

        pool_store = await PostgresOperationalStore.from_dsn(postgres_dsn, min_size=1, max_size=4)
        store, backend = pool_store, "postgresql"
    else:
        store, backend = SqliteOperationalStore(workdir / "bas-lab.sqlite3"), "sqlite"
    await store.initialize()
    audit = RecordingAuditSink()
    transport = httpx.ASGITransport(app=app_factory(store, audit))
    async with httpx.AsyncClient(transport=transport, base_url="http://lab.invalid") as client:
        lab = Lab(client=client, store=store, audit=audit, backend=backend)
        if pool_store is not None:
            lab.pg_pool = pool_store._pool
        try:
            await _seed(lab)
            yield lab
        finally:
            if pool_store is not None:
                await pool_store.close()
