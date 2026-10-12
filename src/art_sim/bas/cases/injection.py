"""Injection and malformed-input attacks against the HTTP boundary."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from functools import partial

import httpx

from art_sim.bas.cases._common import blocked, breached
from art_sim.bas.corpus import MALFORMED_TEXT, SQL_INJECTION
from art_sim.bas.lab import SCENARIO, Lab, bearer
from art_sim.bas.models import AttackCase, Category, Observation, Verdict
from art_sim.platform.models import SimulationRunStatus

ATTACKER = "globex"
_ERROR_LEAK = re.compile(
    r"(traceback|sqlite3?\.|asyncpg|psycopg|syntax error|sqlalchemy|pydantic_core|File \")",
    re.IGNORECASE,
)
Probe = Callable[[Lab, str], Awaitable[httpx.Response]]


async def _surface(
    lab: Lab, probe: Probe, payloads: tuple[str, ...], expect: set[int]
) -> Observation:
    """Fire every payload at one input surface; no 5xx, no error leakage, state intact."""
    victim = await lab.store.get_run(lab.victim_runs["acme"])
    last = None
    refused = 0
    for payload in payloads:
        try:
            response = await probe(lab, payload)
        except Exception:  # noqa: BLE001 - the client refusing to emit a payload is not a breach
            refused += 1
            continue
        last = response
        status = response.status_code
        text = response.text
        if status >= 500:
            return breached(response, f"payload caused HTTP {status}")
        if _ERROR_LEAK.search(text):
            return breached(response, "response leaks internal error details")
        if status not in expect:
            return breached(response, f"unexpected HTTP {status} (allowed: {sorted(expect)})")
    if last is None:
        return Observation(Verdict.ERROR, "the client refused every payload; nothing was tested")
    after = await lab.store.get_run(lab.victim_runs["acme"])
    if after.status is not SimulationRunStatus.WAITING_APPROVAL or after != victim:
        return breached(last, "victim run changed")
    await lab.store.list_runs(
        limit=1, offset=0, status=None, organization_id=ATTACKER
    )  # tables intact
    return blocked(
        last,
        f"{len(payloads) - refused} payloads sent ({refused} refused client-side): statuses within {sorted(expect)}, no leakage",
    )


def _scenario_body(lab: Lab, payload: str) -> Awaitable[httpx.Response]:
    return lab.request(
        "POST",
        "/api/v1/simulations",
        headers=bearer("operator", "mallory", ATTACKER),
        json={"scenario_id": payload},
    )


def _status_query(lab: Lab, payload: str) -> Awaitable[httpx.Response]:
    return lab.request(
        "GET",
        "/api/v1/simulations",
        headers=bearer("operator", "mallory", ATTACKER),
        params={"status": payload},
    )


def _limit_query(lab: Lab, payload: str) -> Awaitable[httpx.Response]:
    return lab.request(
        "GET",
        "/api/v1/simulations",
        headers=bearer("operator", "mallory", ATTACKER),
        params={"limit": payload, "offset": payload},
    )


def _idempotency_header(lab: Lab, payload: str) -> Awaitable[httpx.Response]:
    return lab.request(
        "POST",
        "/api/v1/simulations",
        headers={**bearer("operator", "mallory", ATTACKER), "Idempotency-Key": payload},
        json={"scenario_id": SCENARIO},
    )


def _path_run_id(lab: Lab, payload: str) -> Awaitable[httpx.Response]:
    return lab.request(
        "GET", f"/api/v1/simulations/{payload}", headers=bearer("operator", "mallory", ATTACKER)
    )


def _approval_reason(lab: Lab, payload: str) -> Awaitable[httpx.Response]:
    # Aimed at the *attacker's own* tenant id space: a foreign run, so it must stay a 404/422.
    return lab.request(
        "POST",
        f"/api/v1/simulations/{lab.victim_runs['acme']}/approval",
        headers=bearer("admin", "mallory", ATTACKER),
        json={"decision": "approved", "reason": (payload * 2)[:512].ljust(10, "x")},
    )


def _bearer_value(lab: Lab, payload: str) -> Awaitable[httpx.Response]:
    return lab.request("GET", "/api/v1/simulations", headers={"Authorization": f"Bearer {payload}"})


async def _crlf_request_id(lab: Lab) -> Observation:
    payload = "abc\r\nSet-Cookie: session=hijacked\r\nX-Injected: 1"
    try:
        response = await lab.request("GET", "/health", headers={"X-Request-ID": payload})
    except Exception as error:  # noqa: BLE001
        return Observation(Verdict.BLOCKED, f"client refused CRLF header ({type(error).__name__})")
    reflected = "set-cookie" in response.headers or "x-injected" in response.headers
    echoed = response.headers.get("X-Request-ID") == payload
    if reflected or echoed:
        return breached(response, "CRLF in X-Request-ID reached the response headers")
    return blocked(response, "untrusted correlation id replaced by a generated one")


async def _oversize_body(lab: Lab) -> Observation:
    response = await lab.request(
        "POST",
        "/api/v1/simulations",
        headers={**bearer("operator", "mallory", ATTACKER), "Content-Type": "application/json"},
        content=b'{"scenario_id":"' + b"A" * 70_000 + b'"}',
    )
    if response.status_code != 413:
        return breached(response, f"70 KB body returned {response.status_code}, expected 413")
    return blocked(response, "oversized body rejected before parsing (413)")


async def _type_confusion(lab: Lab) -> Observation:
    headers = {**bearer("operator", "mallory", ATTACKER), "Content-Type": "application/json"}
    bodies = (
        b'{"scenario_id": ["shadow-demo"]}',
        b'{"scenario_id": {"$ne": null}}',
        b'{"scenario_id": 1e999}',
        b'{"scenario_id": null}',
        b'{"scenario_id": "shadow-demo", "scenario_id": "../x"}',
        b'{"__proto__": {"admin": true}, "scenario_id": "shadow-demo"}',
        b"[" * 5000 + b"]" * 5000,
        b"\xff\xfe\x00not-json",
        b"",
    )
    last = None
    for body in bodies:
        last = await lab.request("POST", "/api/v1/simulations", headers=headers, content=body)
        if last.status_code >= 500:
            return breached(last, f"malformed JSON caused HTTP {last.status_code}")
        if last.status_code == 202 and b"__proto__" not in body and b"../x" not in body:
            return breached(last, "a malformed body was accepted")
    health = await lab.request("GET", "/health")
    if health.status_code != 200 or last is None:
        return breached(health, "service unhealthy after malformed bodies")
    return blocked(last, f"{len(bodies)} malformed bodies refused; service still healthy")


def injection_cases() -> list[AttackCase]:
    """All injection / malformed-input attacks, in a stable order."""
    sql, junk = SQL_INJECTION, MALFORMED_TEXT
    surfaces: list[tuple[str, str, Probe, tuple[str, ...], set[int], bool]] = [
        ("SCENARIO", "scenario_id (JSON body)", _scenario_body, sql + junk, {422}, False),
        ("STATUS", "status (query)", _status_query, sql + junk, {422}, False),
        ("PAGING", "limit/offset (query)", _limit_query, sql + junk, {422}, False),
        ("IDEMPOTENCY", "Idempotency-Key (header)", _idempotency_header, sql, {202, 422}, False),
        ("RUNID", "run_id (path)", _path_run_id, sql + junk, {404, 422}, False),
        ("REASON", "approval reason (JSON body)", _approval_reason, sql + junk, {404}, True),
        ("BEARER", "Authorization bearer value", _bearer_value, sql + junk, {401}, True),
    ]
    cases = [
        AttackCase(
            f"INJ-{key}",
            Category.INJECTION,
            "T1190 Exploit Public-Facing Application",
            f"SQL / path / template injection through {label}",
            partial(_surface, probe=probe, payloads=payloads, expect=expect),
            expect_detection=detect,
            payload=" | ".join(payloads)[:512],
            attacker_tenant=ATTACKER,
            victim_tenant="acme",
        )
        for key, label, probe, payloads, expect, detect in surfaces
    ]
    cases += [
        AttackCase(
            "INJ-CRLF",
            Category.INJECTION,
            "T1190 Exploit Public-Facing Application",
            "CRLF header injection through X-Request-ID",
            _crlf_request_id,
            payload="abc\\r\\nSet-Cookie: session=hijacked",
        ),
        AttackCase(
            "INJ-OVERSIZE",
            Category.INJECTION,
            "T1499 Endpoint Denial of Service",
            "70 KB request body",
            _oversize_body,
            attacker_tenant=ATTACKER,
        ),
        AttackCase(
            "INJ-TYPES",
            Category.INJECTION,
            "T1190 Exploit Public-Facing Application",
            "JSON type confusion, duplicate keys, 5000-deep nesting, invalid encoding",
            _type_confusion,
            attacker_tenant=ATTACKER,
        ),
    ]
    return cases
