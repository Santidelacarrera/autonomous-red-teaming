"""The scenario catalogue: every attack belongs to a scenario with an objective and a criterion."""

from __future__ import annotations

from pathlib import Path

import pytest

from art_sim.api.app import create_app  # noqa: F401  (import check: the app under test exists)
from art_sim.bas.authorization import GrantedAuthorization
from art_sim.bas.models import Verdict
from art_sim.bas.runner import catalogue, run_campaign
from art_sim.bas.scenarios import (
    SCENARIOS,
    ScenarioStatus,
    cases_of,
    render_scenarios_markdown,
    scenario_status,
)

pytest_plugins = ["bas_plugin"]  # provides the `bas_grant` fixture

REPO = Path(__file__).resolve().parents[2]
CASE_IDS = [case.case_id for case in catalogue()]


def test_scenario_ids_are_unique_and_ordered() -> None:
    ids = [s.scenario_id for s in SCENARIOS]
    assert len(ids) == len(set(ids)) == 10
    assert ids == sorted(ids)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_every_scenario_states_an_objective_and_a_success_criterion(scenario) -> None:  # type: ignore[no-untyped-def]
    assert len(scenario.objective) >= 40, "the attacker's objective must be spelled out"
    assert len(scenario.success_criterion) >= 40, "the criterion must be measurable, not a slogan"
    assert len(scenario.failure_means) >= 15
    assert scenario.name and cases_of(scenario, CASE_IDS), "a scenario with no cases proves nothing"


def test_every_case_belongs_to_exactly_one_scenario() -> None:
    owners: dict[str, list[str]] = {case_id: [] for case_id in CASE_IDS}
    for scenario in SCENARIOS:
        for case_id in cases_of(scenario, CASE_IDS):
            owners[case_id].append(scenario.scenario_id)
    orphans = [c for c, o in owners.items() if not o]
    doubles = {c: o for c, o in owners.items() if len(o) > 1}
    assert not orphans, f"cases without a scenario: {orphans}"
    assert not doubles, f"cases in several scenarios: {doubles}"


def test_scenario_prefixes_match_real_cases() -> None:
    for scenario in SCENARIOS:
        for prefix in scenario.case_prefixes:
            hits = [
                c
                for c in CASE_IDS
                if c == prefix or (prefix.endswith("*") and c.startswith(prefix[:-1]))
            ]
            assert hits, f"{scenario.scenario_id}: '{prefix}' matches no case"


def test_scenario_family_matches_its_cases() -> None:
    by_id = {case.case_id: case for case in catalogue()}
    for scenario in SCENARIOS:
        families = {by_id[c].category for c in cases_of(scenario, CASE_IDS)}
        # SCN-05 mixes an injection case into the authentication family on purpose.
        assert scenario.category in families, scenario.scenario_id


def test_committed_scenario_document_is_generated_from_the_code() -> None:
    committed = (REPO / "docs" / "bas-scenarios.md").read_text(encoding="utf-8")
    assert committed == render_scenarios_markdown(CASE_IDS), (
        "docs/bas-scenarios.md is stale: run `python -m art_sim.bas --list-scenarios > docs/bas-scenarios.md`"
    )


def test_document_names_the_organization_and_the_lab_only_scope() -> None:
    text = render_scenarios_markdown(CASE_IDS)
    assert "Nexus Security & AI Lab" in text and "synthetic local lab" in text


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ([], ScenarioStatus.NOT_RUN),
        ([Verdict.BLOCKED, Verdict.BLOCKED], ScenarioStatus.HELD),
        ([Verdict.BLOCKED, Verdict.GAP], ScenarioStatus.FINDING),
        ([Verdict.GAP, Verdict.BREACHED], ScenarioStatus.FAIL),
        ([Verdict.BLOCKED, Verdict.ERROR], ScenarioStatus.FAIL),
    ],
)
def test_scenario_status_folds_case_verdicts(
    verdicts: list[Verdict], expected: ScenarioStatus
) -> None:
    assert scenario_status(verdicts) is expected


async def test_report_carries_one_result_per_scenario(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant)
    statuses = {s.scenario_id: s.status for s in report.scenarios}
    assert len(statuses) == 10
    assert (
        statuses["SCN-10"] is ScenarioStatus.FINDING
    )  # no row-level security: reported, not hidden
    assert all(v is ScenarioStatus.HELD for k, v in statuses.items() if k != "SCN-10")


async def test_scenarios_not_selected_are_reported_as_not_run(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    report = await run_campaign(tmp_path, authorization=bas_grant, only={"TEN-NO-CREDS"})
    statuses = {s.scenario_id: s.status for s in report.scenarios}
    assert statuses["SCN-05"] is ScenarioStatus.HELD  # judged only by the cases that ran
    assert statuses["SCN-01"] is ScenarioStatus.NOT_RUN


async def test_a_removed_control_fails_the_scenario_that_guards_it(
    tmp_path: Path, bas_grant: GrantedAuthorization
) -> None:
    from test_bas_framework import _leaky_isolation

    report = await run_campaign(tmp_path, authorization=bas_grant, app_factory=_leaky_isolation)
    statuses = {s.scenario_id: s.status for s in report.scenarios}
    assert statuses["SCN-01"] is ScenarioStatus.FAIL
    assert statuses["SCN-04"] is ScenarioStatus.FAIL
    # A foreign approval now succeeds, so even the injection case that aims at a foreign run
    # (SCN-06) sees the breach; controls that do not touch tenancy are unaffected.
    assert statuses["SCN-06"] is ScenarioStatus.FAIL
    assert statuses["SCN-07"] is ScenarioStatus.HELD
    assert statuses["SCN-08"] is ScenarioStatus.HELD
