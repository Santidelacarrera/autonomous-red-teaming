"""The risk justification must reconcile with the score it explains, for every scenario."""

from __future__ import annotations

import pytest

from art_sim.attack.explain import explain_risk
from art_sim.attack.risk import RiskScorer, RiskScoringSettings
from art_sim.demo.lab import lab_scenario
from art_sim.worker.fixtures import shadow_scenario_catalog

SCENARIOS = (*shadow_scenario_catalog(), lab_scenario())


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_explanation_reconciles_with_the_score(scenario) -> None:  # type: ignore[no-untyped-def]
    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assessment = RiskScorer().assess(path, scenario.graph.assets)
    explanation = explain_risk(path, scenario.graph.assets, assessment)
    assert explanation.reconciles
    assert explanation.score == assessment.score
    assert len(explanation.factors) == 7
    assert all(factor.justification for factor in explanation.factors)


@pytest.mark.parametrize(
    "weights",
    [
        RiskScoringSettings(criticality_weight=0.0),
        RiskScoringSettings(path_length_penalty=10.0),
        RiskScoringSettings(crown_jewel_weight=5.0, relation_weight=5.0),
    ],
    ids=["no-criticality", "heavy-penalty", "heavy-clamped"],
)
def test_reconciliation_holds_under_custom_weights_and_clamping(weights: RiskScoringSettings) -> None:
    scenario = lab_scenario()
    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assessment = RiskScorer(weights).assess(path, scenario.graph.assets)
    assert explain_risk(path, scenario.graph.assets, assessment).reconciles


def test_a_score_that_disagrees_with_its_factors_does_not_reconcile() -> None:
    scenario = lab_scenario()
    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assessment = RiskScorer().assess(path, scenario.graph.assets)
    forged = assessment.model_copy(update={"score": assessment.score + 10.0})
    assert not explain_risk(path, scenario.graph.assets, forged).reconciles


def test_lab_numbers_match_a_hand_calculation() -> None:
    """25 + 20*(4.1/6) + 15 + 5 + 5 - 5 = 58.67; the CVSS factor honestly states it has no evidence."""
    scenario = lab_scenario()
    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assessment = RiskScorer().assess(path, scenario.graph.assets)
    assert assessment.score == 58.67
    by_name = {f.name: f for f in explain_risk(path, scenario.graph.assets, assessment).factors}
    assert by_name["Asset criticality"].value == 25.0
    assert by_name["Vulnerability severity (CVSS)"].value == 0.0
    assert "No scanner evidence" in by_name["Vulnerability severity (CVSS)"].justification
    assert by_name["Path length penalty"].signed_value == -5.0
