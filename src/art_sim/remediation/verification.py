"""Post-remediation verification against an immutable simulated graph copy."""

from __future__ import annotations

from uuid import UUID

from art_sim.attack.risk import RiskScorer
from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.blast_radius.calculator import BlastRadiusCalculator
from art_sim.domain.exceptions import TopologyNotFoundError, VerificationError
from art_sim.domain.models import AssetRelationship
from art_sim.remediation.models import NormalizedRemediation, VerificationResult, VerificationStatus


class RemediationVerifier:
    """Prove whether a candidate removed a modeled route; never alters a live graph."""

    def __init__(
        self,
        risk_scorer: RiskScorer | None = None,
        blast_calculator: BlastRadiusCalculator | None = None,
    ) -> None:
        """Inject deterministic analysis collaborators for testability."""
        self._risk_scorer = risk_scorer or RiskScorer()
        self._blast_calculator = blast_calculator or BlastRadiusCalculator()

    def verify(
        self, graph: SimulatedAttackGraph, source_asset_id: UUID, remediation: NormalizedRemediation
    ) -> VerificationResult:
        """Remove the proposed relation in-memory and recompute path, risk, and blast radius."""
        try:
            before_path = graph.find_shortest_path_to_crown_jewel(source_asset_id)
        except TopologyNotFoundError as error:
            raise VerificationError("Cannot verify a remediation when no baseline path exists") from error
        before_risk = self._risk_scorer.assess(before_path, graph.assets)
        before_blast = self._blast_calculator.calculate(graph, source_asset_id)
        relation = AssetRelationship(
            source_asset_id=remediation.source_asset_id,
            target_asset_id=remediation.target_asset_id,
            relationship_type=remediation.relationship_type,
        )
        simulated_after = graph.without_relationship(relation)
        after_blast = self._blast_calculator.calculate(simulated_after, source_asset_id)
        try:
            after_path = simulated_after.find_shortest_path_to_crown_jewel(source_asset_id)
        except TopologyNotFoundError:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                paths_removed=1,
                remaining_paths=0,
                risk_before=before_risk.score,
                risk_after=0.0,
                risk_reduction=before_risk.score,
                blast_radius_before=before_blast,
                blast_radius_after=after_blast,
            )
        after_risk = self._risk_scorer.assess(after_path, simulated_after.assets)
        reduction = max(0.0, round(before_risk.score - after_risk.score, 2))
        return VerificationResult(
            status=VerificationStatus.PARTIALLY_VERIFIED if reduction > 0.0 else VerificationStatus.FAILED,
            paths_removed=0,
            remaining_paths=1,
            risk_before=before_risk.score,
            risk_after=after_risk.score,
            risk_reduction=reduction,
            blast_radius_before=before_blast,
            blast_radius_after=after_blast,
        )
