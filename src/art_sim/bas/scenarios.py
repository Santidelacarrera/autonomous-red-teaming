"""Scenario catalogue: what each group of attacks tries to achieve and what counts as success.

An *attack case* is one reproducible attempt; a *scenario* is the question a defender asks
("can one tenant read another's runs?"). Each scenario states the attacker's objective, the
**success criterion** (when the control is considered effective), and what a failure means.
Every case belongs to exactly one scenario; ``tests/security/test_bas_scenarios.py`` enforces it
and keeps ``docs/bas-scenarios.md`` identical to :func:`render_scenarios_markdown`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from art_sim.bas.models import Category, Verdict


class ScenarioStatus(StrEnum):
    """Result of a scenario once all of its cases have run."""

    HELD = "held"  # success criterion met by every case: the control held
    FINDING = "finding"  # nothing breached, but a defence-in-depth gap remains
    FAIL = "fail"  # at least one control failed (or a case could not conclude)
    NOT_RUN = "not_run"  # none of its cases were selected


@dataclass(frozen=True)
class Scenario:
    """One question about one trust boundary."""

    scenario_id: str
    name: str
    category: Category
    objective: str  # what the simulated attacker tries to obtain
    success_criterion: str  # when the defence is considered effective (measurable)
    failure_means: str  # consequence if the criterion is not met
    case_prefixes: tuple[str, ...]  # case ids matched by exact id or by "PREFIX*"


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "SCN-01",
        "Direct cross-tenant access to a run",
        Category.TENANT_ISOLATION,
        "Read, cancel or approve another organization's simulation run through any of the 11 "
        "routes that name a run, using the strongest role (admin) of a different tenant.",
        "Every route answers 404 identical to an unknown run, the victim's state is unchanged, "
        "and the probe is recorded as a denial in the platform's audit stream.",
        "Disclosure or manipulation of another customer's security findings.",
        ("TEN-ROUTE-*",),
    ),
    Scenario(
        "SCN-02",
        "Cross-tenant discovery and enumeration",
        Category.TENANT_ISOLATION,
        "Learn that another tenant's runs exist (list/filter parameters, or telling foreign "
        "identifiers apart from unknown ones).",
        "No list variant contains the victim's run id, and foreign and unknown identifiers are "
        "indistinguishable by status and body.",
        "An existence oracle that lets an attacker map another tenant.",
        ("TEN-LIST-LEAK", "TEN-ENUM-ORACLE"),
    ),
    Scenario(
        "SCN-03",
        "Organization spoofing and idempotency collision",
        Category.TENANT_ISOLATION,
        "Choose the organization of a request (headers, body) or receive the victim's run by "
        "replaying its Idempotency-Key.",
        "The organization comes only from the verified credential: header and body hints are "
        "ignored or rejected, and equal idempotency keys yield separate runs per tenant.",
        "A client could act inside, or read from, an organization it does not belong to.",
        ("TEN-HDR-SPOOF", "TEN-BODY-SPOOF", "TEN-IDEMPOTENCY"),
    ),
    Scenario(
        "SCN-04",
        "High-impact action across tenant or role boundary",
        Category.TENANT_ISOLATION,
        "Approve or cancel a pending high-impact action from another tenant, or with a "
        "read-only role inside the right tenant.",
        "Foreign approval is refused (404) and a viewer receives 403 for approve, cancel and "
        "create; the run still awaits its own tenant's human decision.",
        "The human-approval control could be bypassed.",
        ("TEN-APPROVAL-XORG", "TEN-VIEWER-ESC"),
    ),
    Scenario(
        "SCN-05",
        "Unauthenticated and malformed credentials",
        Category.TENANT_ISOLATION,
        "Reach a protected route with no credential, an empty one, the wrong scheme or injection "
        "text in the bearer value.",
        "Every variant returns 401 without 5xx or internal error text, and each is logged.",
        "Unauthenticated access to run data.",
        ("TEN-NO-CREDS", "INJ-BEARER"),
    ),
    Scenario(
        "SCN-06",
        "Injection through HTTP inputs",
        Category.INJECTION,
        "Alter a query, path or stored value with SQL, path-traversal or template payloads in "
        "every caller-controlled input (scenario id, status, paging, idempotency key, run id, "
        "approval reason).",
        "No payload yields a 5xx or internal error text; status codes stay within the documented "
        "set; the victim run and the data store are intact afterwards.",
        "Data disclosure or corruption, or denial of service by unhandled input.",
        ("INJ-SCENARIO", "INJ-STATUS", "INJ-PAGING", "INJ-IDEMPOTENCY", "INJ-RUNID", "INJ-REASON"),
    ),
    Scenario(
        "SCN-07",
        "Protocol and resource abuse",
        Category.INJECTION,
        "Split response headers with CRLF in a correlation id, send an oversized body, or send "
        "malformed and deeply nested JSON.",
        "The correlation id is replaced, the oversized body is refused with 413, malformed bodies "
        "are refused without 5xx, and the service is still healthy afterwards.",
        "Header injection, resource exhaustion or a crash from crafted requests.",
        ("INJ-CRLF", "INJ-OVERSIZE", "INJ-TYPES"),
    ),
    Scenario(
        "SCN-08",
        "Prompt injection against the planner context",
        Category.PROMPT_INJECTION,
        "Plant instruction-like text (including zero-width and look-alike obfuscation) in asset "
        "names, tags and edge properties so that an LLM-backed planner would obey it.",
        "The planner context contains only allow-listed fields (control), and the text sanitizer "
        "neutralises every obfuscated instruction (defence in depth).",
        "Attacker-controlled data steering an automated agent.",
        ("PI-ALLOWLIST", "PI-SANITIZE"),
    ),
    Scenario(
        "SCN-09",
        "Stored attacker text as active content",
        Category.PROMPT_INJECTION,
        "Store hostile text through the approval reason and have it returned as active content "
        "or copied into the security audit stream.",
        "Stored text comes back only as application/json with nosniff and never appears in the "
        "platform's audit events.",
        "Stored cross-site scripting or audit-log poisoning.",
        ("PI-ROUNDTRIP",),
    ),
    Scenario(
        "SCN-10",
        "Tenant boundary in the data layer",
        Category.DATASTORE,
        "Reach another tenant's rows through the organization filter or, with the application's "
        "own database role, through an unscoped query.",
        "Hostile filter values match nothing, and the database itself refuses an unscoped read "
        "(row-level security enabled, role without BYPASSRLS).",
        "Isolation that depends on every code path remembering a filter.",
        ("DS-ORG-SQLI", "DS-RLS-POSTURE"),
    ),
)


def cases_of(scenario: Scenario, all_case_ids: list[str]) -> tuple[str, ...]:
    """Case ids belonging to ``scenario``, in catalogue order."""

    def matches(case_id: str) -> bool:
        return any(
            case_id == p or (p.endswith("*") and case_id.startswith(p[:-1]))
            for p in scenario.case_prefixes
        )

    return tuple(case_id for case_id in all_case_ids if matches(case_id))


def scenario_status(verdicts: list[Verdict]) -> ScenarioStatus:
    """Fold case verdicts into one scenario status."""
    if not verdicts:
        return ScenarioStatus.NOT_RUN
    if any(v in (Verdict.BREACHED, Verdict.ERROR) for v in verdicts):
        return ScenarioStatus.FAIL
    if any(v is Verdict.GAP for v in verdicts):
        return ScenarioStatus.FINDING
    return ScenarioStatus.HELD


def render_scenarios_markdown(all_case_ids: list[str]) -> str:
    """The committed ``docs/bas-scenarios.md``, generated so it cannot drift from the code."""
    lines = [
        "# BAS scenario catalogue",
        "",
        (
            "_Nexus Security & AI Lab — generated by `python -m art_sim.bas --list-scenarios`; "
            "do not edit by hand (a test keeps it identical to the code)._"
        ),
        "",
        (
            "Every attack runs **only against the synthetic local lab**, and only with a valid "
            "written authorization (see [bas.md](bas.md)). A scenario is *held* when all its "
            "cases are blocked, *finding* when nothing was breached but a defence-in-depth gap "
            "remains, and *fail* when a control failed or a case could not conclude."
        ),
        "",
        "| Scenario | Family | Cases |",
        "|---|---|---|",
    ]
    for scenario in SCENARIOS:
        lines.append(
            f"| [{scenario.scenario_id}](#{scenario.scenario_id.lower()}) {scenario.name} | "
            f"{scenario.category.value} | {len(cases_of(scenario, all_case_ids))} |"
        )
    for scenario in SCENARIOS:
        lines += [
            "",
            f"## {scenario.scenario_id}",
            "",
            f"**{scenario.name}** ({scenario.category.value})",
            "",
            f"- **Objective (attacker):** {scenario.objective}",
            f"- **Success criterion (defence):** {scenario.success_criterion}",
            f"- **If it fails:** {scenario.failure_means}",
            "- **Cases:** " + ", ".join(f"`{c}`" for c in cases_of(scenario, all_case_ids)),
        ]
    return "\n".join(lines) + "\n"
