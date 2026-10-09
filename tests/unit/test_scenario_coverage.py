"""Coverage for the enriched scenario catalog and MITRE technique mappings."""

from __future__ import annotations

import pytest

from art_sim.agents.planner import MitrePathPlanner
from art_sim.attack.risk import RiskScorer
from art_sim.domain.models import RelationshipType
from art_sim.security.sanitizer import PromptInjectionSanitizer
from art_sim.worker.fixtures import shadow_scenario_catalog

PLANNER = MitrePathPlanner()
SANITIZER = PromptInjectionSanitizer()

EXPECTED_TECHNIQUES = {
    "shadow-container-breakout": {"T1611", "T1552"},
    "shadow-iam-privilege-chain": {"T1548", "T1210"},
    "shadow-credential-harvest": {"T1552", "T1078"},
}


def test_catalog_has_unique_scenario_ids() -> None:
    ids = [scenario.scenario_id for scenario in shadow_scenario_catalog()]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 8


def test_every_relationship_type_has_a_mitre_mapping() -> None:
    # Every relationship the graph can express must be plannable (no KeyError at runtime).
    for relationship_type in RelationshipType:
        assert relationship_type in PLANNER._TECHNIQUES


@pytest.mark.parametrize("scenario_id,expected", EXPECTED_TECHNIQUES.items())
async def test_new_scenarios_plan_with_expected_techniques(
    scenario_id: str, expected: set[str]
) -> None:
    scenario = next(s for s in shadow_scenario_catalog() if s.scenario_id == scenario_id)
    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assets_by_id = {asset.asset_id: asset for asset in scenario.graph.assets}
    ordered_assets = tuple(assets_by_id[asset_id] for asset_id in path.asset_ids)
    context = SANITIZER.build_topology_context(path, ordered_assets)

    plan = await PLANNER.create_plan(context, ())
    produced = {step.technique.technique_id for step in plan.steps}
    assert expected.issubset(produced)
    # Every step maps to a non-destructive simulated action.
    assert all(step.action.value.startswith(("observe", "validate", "simulate")) for step in plan.steps)


@pytest.mark.parametrize("scenario_id", list(EXPECTED_TECHNIQUES))
def test_new_scenarios_produce_bounded_risk(scenario_id: str) -> None:
    scenario = next(s for s in shadow_scenario_catalog() if s.scenario_id == scenario_id)
    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assets_by_id = {asset.asset_id: asset for asset in scenario.graph.assets}
    ordered_assets = tuple(assets_by_id[asset_id] for asset_id in path.asset_ids)
    result = RiskScorer().assess(path, ordered_assets, ())
    assert 0.0 <= result.score <= 100.0
