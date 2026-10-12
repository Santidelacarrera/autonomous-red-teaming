"""Cross-tenant attacks: can tenant ``globex`` read or change what belongs to ``acme``?

The attacker is the strongest legitimate identity of the attacking tenant (an *admin*), so a
pass means isolation does not depend on role weakness. Defence expectations:

* a foreign run is indistinguishable from a missing one (no existence oracle);
* nothing the attacker controls (header, query, body) can choose the organization;
* the victim's state is byte-for-byte unchanged afterwards;
* the probe is visible in the platform's own audit stream.
"""

from __future__ import annotations

from uuid import UUID

from art_sim.bas.cases._common import blocked, breached, shape
from art_sim.bas.lab import SCENARIO, Lab, bearer
from art_sim.bas.models import AttackCase, Category, Observation, Verdict
from art_sim.platform.models import SimulationRunStatus

ATTACKER, VICTIM = "globex", "acme"
APPROVE = {"decision": "approved", "reason": "Reviewed the simulated countermeasure evidence."}
UNKNOWN_RUN = UUID(int=0xDEAD)

# (method, path suffix, body) for every route that names a run.
RUN_ROUTES: tuple[tuple[str, str, dict[str, str] | None], ...] = (
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
)


async def _victim_unchanged(lab: Lab) -> bool:
    run = await lab.store.get_run(lab.victim_runs[VICTIM])
    return run.status is SimulationRunStatus.WAITING_APPROVAL


def _foreign_route(method: str, suffix: str, body: dict[str, str] | None) -> AttackCase:
    label = suffix or "/"

    async def run(lab: Lab) -> Observation:
        attacker = bearer("admin", "mallory", ATTACKER)
        target = f"/api/v1/simulations/{lab.victim_runs[VICTIM]}{suffix}"
        reference = f"/api/v1/simulations/{UNKNOWN_RUN}{suffix}"
        hit = await lab.request(method, target, headers=attacker, json=body)
        miss = await lab.request(method, reference, headers=attacker, json=body)
        if hit.status_code != 404:
            return breached(hit, f"{method} {label} on a foreign run returned {hit.status_code}")
        if shape(hit) != shape(miss):
            return breached(hit, "foreign and unknown runs are distinguishable (existence oracle)")
        if not await _victim_unchanged(lab):
            return breached(hit, "the victim run changed state")
        return blocked(hit, f"{method} {label}: 404, identical to an unknown run, state intact")

    return AttackCase(
        f"TEN-ROUTE-{method}{suffix.replace('/', '-') or '-run'}".upper(),
        Category.TENANT_ISOLATION,
        "T1078 Valid Accounts / T1213 Data from Information Repositories",
        f"Foreign tenant admin calls {method} {label} on the victim's run",
        run,
        expect_detection=True,
        attacker_tenant=ATTACKER,
        victim_tenant=VICTIM,
    )


async def _list_leak(lab: Lab) -> Observation:
    attacker = bearer("admin", "mallory", ATTACKER)
    victim_id = str(lab.victim_runs[VICTIM])
    last = None
    for params in (
        {"limit": "200"},
        {"limit": "200", "offset": "0", "status": "waiting_approval"},
        {"limit": "200", "organization_id": VICTIM},
        {"limit": "200", "organization_id": "*"},
    ):
        last = await lab.request("GET", "/api/v1/simulations", headers=attacker, params=params)
        if victim_id in last.text:
            return breached(last, f"victim run listed with params {sorted(params)}")
    if last is None:
        return Observation(Verdict.ERROR, "no list variant was sent")
    return blocked(last, "no list variant exposes the victim's run")


async def _header_spoof(lab: Lab) -> Observation:
    target = f"/api/v1/simulations/{lab.victim_runs[VICTIM]}"
    spoof = {
        **bearer("admin", "mallory", ATTACKER),
        "X-Organization-Id": VICTIM,
        "X-Tenant-Id": VICTIM,
        "X-Forwarded-Organization": VICTIM,
        "X-Org": VICTIM,
    }
    response = await lab.request("GET", target, headers=spoof)
    if response.status_code != 404:
        return breached(response, f"organization header spoof returned {response.status_code}")
    return blocked(response, "organization is taken from the credential only")


async def _body_spoof(lab: Lab) -> Observation:
    before = len(
        await lab.store.list_runs(limit=200, offset=0, status=None, organization_id=VICTIM)
    )
    response = await lab.request(
        "POST",
        "/api/v1/simulations",
        headers=bearer("operator", "mallory", ATTACKER),
        json={"scenario_id": SCENARIO, "organization_id": VICTIM},
    )
    after = len(await lab.store.list_runs(limit=200, offset=0, status=None, organization_id=VICTIM))
    if response.status_code == 202 or after != before:
        return breached(response, "a body field chose the organization of a new run")
    return blocked(
        response, "unknown body fields are rejected; no run created in the victim tenant"
    )


async def _idempotency_collision(lab: Lab) -> Observation:
    shared_id = f"bas-replay-{VICTIM}-{ATTACKER}"
    first = await lab.request(
        "POST",
        "/api/v1/simulations",
        headers={**bearer("operator", "alice", VICTIM), "Idempotency-Key": shared_id},
        json={"scenario_id": SCENARIO},
    )
    second = await lab.request(
        "POST",
        "/api/v1/simulations",
        headers={**bearer("operator", "mallory", ATTACKER), "Idempotency-Key": shared_id},
        json={"scenario_id": SCENARIO},
    )
    if first.status_code != 202 or second.status_code != 202:
        return Observation(Verdict.ERROR, "setup requests were not accepted", second.status_code)
    if second.json()["run_id"] == first.json()["run_id"]:
        return breached(
            second, "the attacker's request returned the victim's run via its idempotency key"
        )
    run = await lab.store.get_run(UUID(second.json()["run_id"]))
    if run.organization_id != ATTACKER:
        return breached(second, "the attacker's run was created in another organization")
    return blocked(second, "the same idempotency key yields separate runs per tenant")


async def _cross_tenant_approval(lab: Lab) -> Observation:
    response = await lab.request(
        "POST",
        f"/api/v1/simulations/{lab.victim_runs[VICTIM]}/approval",
        headers=bearer("admin", "mallory", ATTACKER),
        json=APPROVE,
    )
    if response.status_code != 404 or not await _victim_unchanged(lab):
        return breached(response, "a foreign admin influenced the victim's approval")
    return blocked(response, "foreign approval refused; run still awaits its own tenant's decision")


async def _viewer_escalation(lab: Lab) -> Observation:
    viewer = bearer("viewer", "vera", VICTIM)
    run_path = f"/api/v1/simulations/{lab.victim_runs[VICTIM]}"
    attempts = (
        await lab.request("POST", f"{run_path}/approval", headers=viewer, json=APPROVE),
        await lab.request("POST", f"{run_path}/cancel", headers=viewer),
        await lab.request(
            "POST", "/api/v1/simulations", headers=viewer, json={"scenario_id": SCENARIO}
        ),
    )
    bad = [r for r in attempts if r.status_code != 403]
    if bad or not await _victim_unchanged(lab):
        return breached(
            bad[0] if bad else attempts[0], "a read-only role performed a privileged action"
        )
    return blocked(attempts[0], "viewer cannot approve, cancel or create (403 x3), state intact")


async def _enumeration_oracle(lab: Lab) -> Observation:
    attacker = bearer("operator", "mallory", ATTACKER)
    foreign = await lab.request(
        "GET", f"/api/v1/simulations/{lab.victim_runs[VICTIM]}", headers=attacker
    )
    missing = await lab.request("GET", f"/api/v1/simulations/{UNKNOWN_RUN}", headers=attacker)
    if shape(foreign) != shape(missing):
        return breached(foreign, "status/body differ between foreign and unknown identifiers")
    return blocked(foreign, "identifiers cannot be enumerated across tenants")


async def _no_credentials(lab: Lab) -> Observation:
    target = f"/api/v1/simulations/{lab.victim_runs[VICTIM]}"
    responses = [
        await lab.request("GET", target),
        await lab.request("GET", target, headers={"Authorization": "Bearer "}),
        await lab.request("GET", target, headers={"Authorization": "Bearer not-a-credential"}),
        await lab.request("GET", target, headers={"Authorization": "Basic YWRtaW46YWRtaW4="}),
    ]
    bad = [r for r in responses if r.status_code != 401]
    if bad:
        return breached(bad[0], f"unauthenticated request returned {bad[0].status_code}")
    return blocked(
        responses[0], "missing, empty, malformed and wrong-scheme credentials all return 401"
    )


def tenant_cases() -> list[AttackCase]:
    """All tenant-isolation attacks, in a stable order."""
    cases = [_foreign_route(method, suffix, body) for method, suffix, body in RUN_ROUTES]
    cases += [
        AttackCase(
            "TEN-LIST-LEAK",
            Category.TENANT_ISOLATION,
            "T1213 Data from Information Repositories",
            "Enumerate the victim's runs through list/filter/organization parameters",
            _list_leak,
            attacker_tenant=ATTACKER,
            victim_tenant=VICTIM,
        ),
        AttackCase(
            "TEN-HDR-SPOOF",
            Category.TENANT_ISOLATION,
            "T1078 Valid Accounts",
            "Choose the organization with request headers",
            _header_spoof,
            expect_detection=True,
            attacker_tenant=ATTACKER,
            victim_tenant=VICTIM,
        ),
        AttackCase(
            "TEN-BODY-SPOOF",
            Category.TENANT_ISOLATION,
            "T1565 Data Manipulation",
            "Create a run inside the victim tenant by naming it in the body",
            _body_spoof,
            attacker_tenant=ATTACKER,
            victim_tenant=VICTIM,
        ),
        AttackCase(
            "TEN-IDEMPOTENCY",
            Category.TENANT_ISOLATION,
            "T1213 Data from Information Repositories",
            "Replay the victim's Idempotency-Key to receive the victim's run",
            _idempotency_collision,
            attacker_tenant=ATTACKER,
            victim_tenant=VICTIM,
        ),
        AttackCase(
            "TEN-APPROVAL-XORG",
            Category.TENANT_ISOLATION,
            "T1565 Data Manipulation",
            "Approve the victim's pending action from another tenant",
            _cross_tenant_approval,
            expect_detection=True,
            attacker_tenant=ATTACKER,
            victim_tenant=VICTIM,
        ),
        AttackCase(
            "TEN-ENUM-ORACLE",
            Category.TENANT_ISOLATION,
            "T1595 Active Scanning",
            "Tell foreign identifiers apart from unknown ones",
            _enumeration_oracle,
            expect_detection=True,
            attacker_tenant=ATTACKER,
            victim_tenant=VICTIM,
        ),
        AttackCase(
            "TEN-VIEWER-ESC",
            Category.TENANT_ISOLATION,
            "T1548 Abuse Elevation Control Mechanism",
            "Viewer role approves, cancels and creates inside its own tenant",
            _viewer_escalation,
            expect_detection=True,
            attacker_tenant=VICTIM,
            victim_tenant=VICTIM,
        ),
        AttackCase(
            "TEN-NO-CREDS",
            Category.TENANT_ISOLATION,
            "T1190 Exploit Public-Facing Application",
            "Call a run route with absent or malformed credentials",
            _no_credentials,
            expect_detection=True,
            victim_tenant=VICTIM,
        ),
    ]
    return cases
