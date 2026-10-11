"""Data-layer attacks: does the database itself enforce a tenant boundary?"""

from __future__ import annotations

from art_sim.bas.corpus import SQL_INJECTION
from art_sim.bas.lab import Lab
from art_sim.bas.models import AttackCase, Category, Observation, Verdict

_TABLES = (
    "simulation_runs",
    "audit_events",
    "simulation_results",
    "simulation_reviews",
    "workflow_checkpoints",
    "api_idempotency",
    "worker_leases",
)


async def _store_injection(lab: Lab) -> Observation:
    leaked = 0
    for payload in SQL_INJECTION:
        rows = await lab.store.list_runs(limit=200, offset=0, status=None, organization_id=payload)
        leaked += len(rows)
    if leaked:
        return Observation(
            Verdict.BREACHED, f"{leaked} rows returned for hostile organization values"
        )
    return Observation(
        Verdict.BLOCKED,
        f"{len(SQL_INJECTION)} hostile organization values matched nothing "
        "(parameter-bound, not interpolated)",
    )


async def _rls_posture(lab: Lab) -> Observation:
    """Measure whether the database refuses an unscoped read. Today it does not: GAP."""
    pool = lab.pg_pool
    if pool is None:
        return Observation(
            Verdict.GAP,
            "SQLite has no row-level security; isolation is enforced only by application filters",
        )
    async with pool.acquire() as conn:
        enabled = await conn.fetch(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname = ANY($1::text[]) AND relkind='r'",
            list(_TABLES),
        )
        role = await conn.fetchrow(
            "SELECT current_user AS name, rolsuper, rolbypassrls FROM pg_roles "
            "WHERE rolname = current_user"
        )
        visible = await conn.fetchval(
            "SELECT count(DISTINCT COALESCE((payload::jsonb)->>'organization_id','default')) "
            "FROM simulation_runs"
        )
    protected = [r["relname"] for r in enabled if r["relrowsecurity"]]
    evidence = (
        f"rls_tables={sorted(protected)} role={role['name']} super={role['rolsuper']} "
        f"bypass={role['rolbypassrls']} tenants_visible_to_one_query={visible}"
    )
    if (
        len(protected) == len(enabled)
        and enabled
        and not (role["rolsuper"] or role["rolbypassrls"])
    ):
        return Observation(
            Verdict.BLOCKED, "row-level security enabled on all tenant tables", evidence=evidence
        )
    return Observation(
        Verdict.GAP,
        f"PostgreSQL enforces no tenant boundary: an unscoped SELECT sees "
        f"{visible} tenants; RLS is off on {len(enabled) - len(protected)} tables",
        evidence=evidence,
    )


def datastore_cases() -> list[AttackCase]:
    """All data-layer attacks, in a stable order."""
    return [
        AttackCase(
            "DS-ORG-SQLI",
            Category.DATASTORE,
            "T1190 Exploit Public-Facing Application",
            "SQL injection through the organization filter of list_runs",
            _store_injection,
            payload=" | ".join(SQL_INJECTION)[:512],
            attacker_tenant="globex",
        ),
        AttackCase(
            "DS-RLS-POSTURE",
            Category.DATASTORE,
            "T1213 Data from Information Repositories",
            "Unscoped read with the application's own database role (defence in depth)",
            _rls_posture,
            attacker_tenant="globex",
            victim_tenant="acme",
        ),
    ]
