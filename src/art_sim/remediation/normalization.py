"""Translate a simulated path into a normalized defensive remediation candidate."""

from __future__ import annotations

from typing import ClassVar
from uuid import NAMESPACE_URL, uuid5

from art_sim.attack.risk import PathRiskAssessment
from art_sim.domain.models import AttackPath, RelationshipType
from art_sim.remediation.models import NormalizedRemediation, RemediationAction


class RemediationPlanner:
    """Choose the highest-impact modeled edge to break without applying a real change."""

    _PRIORITY: ClassVar[dict[RelationshipType, int]] = {
        RelationshipType.CONTAINER_ESCAPE: 100,
        RelationshipType.CREDENTIAL_ACCESS: 90,
        RelationshipType.IAM_ASSUME_ROLE: 80,
        RelationshipType.ASSUMES_ROLE: 75,
        RelationshipType.TRUSTS: 60,
        RelationshipType.ACCESS: 55,
        RelationshipType.EXPOSES: 50,
        RelationshipType.NETWORK_REACHABLE: 40,
        RelationshipType.HOSTS: 30,
    }

    def propose(self, path: AttackPath, assessment: PathRiskAssessment) -> NormalizedRemediation:
        """Build a deterministic proposal for the highest-priority path edge."""
        edge = max(
            path.steps,
            key=lambda step: (self._PRIORITY[step.relationship_type], str(step.source_asset_id)),
        )
        action = (
            RemediationAction.RESTRICT_TRUST
            if edge.relationship_type in {RelationshipType.IAM_ASSUME_ROLE, RelationshipType.ASSUMES_ROLE, RelationshipType.TRUSTS}
            else RemediationAction.DISABLE_RELATIONSHIP
        )
        remediation_id = uuid5(
            NAMESPACE_URL,
            ":".join(
                (
                    "art-sim-remediation-v1",
                    str(edge.source_asset_id),
                    edge.relationship_type.value,
                    str(edge.target_asset_id),
                    action.value,
                )
            ),
        )
        return NormalizedRemediation(
            remediation_id=remediation_id,
            action=action,
            source_asset_id=edge.source_asset_id,
            target_asset_id=edge.target_asset_id,
            relationship_type=edge.relationship_type,
            resource=f"graph-edge:{edge.source_asset_id}:{edge.relationship_type.value}:{edge.target_asset_id}",
            reason="Break the highest-risk simulated traversal relation to the crown jewel.",
            expected_risk_reduction=assessment.score,
        )
