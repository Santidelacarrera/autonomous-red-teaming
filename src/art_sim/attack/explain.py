"""Human-readable justification of a path risk score, derived from the scorer's own inputs.

``RiskScorer`` returns numbers; reviewers also need to know *why*. This module re-derives each
component's inputs from the same typed path and assets and states them in plain language next
to the value the scorer actually produced. It never recomputes the score independently: the
rows carry the scorer's ``RiskBreakdown`` values, and ``reconciles`` proves the displayed parts
add up to the displayed total, so an explanation can never silently drift from the number.
"""

from __future__ import annotations

from dataclasses import dataclass

from art_sim.attack.risk import PathRiskAssessment, RiskScorer
from art_sim.domain.models import Asset, AttackPath, Criticality, RelationshipType

_CRITICALITY_RANK = {
    Criticality.LOW: 1,
    Criticality.MEDIUM: 2,
    Criticality.HIGH: 3,
    Criticality.CRITICAL: 4,
}


@dataclass(frozen=True)
class RiskFactor:
    """One scored component: its value, its ceiling, and the evidence behind it."""

    name: str
    value: float
    maximum: float
    justification: str

    @property
    def signed_value(self) -> float:
        """Penalties reduce the score; everything else adds to it."""
        return -self.value if self.name == "Path length penalty" else self.value


@dataclass(frozen=True)
class RiskExplanation:
    """The full justification of one assessment."""

    score: float
    total_before_clamp: float
    factors: tuple[RiskFactor, ...]

    @property
    def reconciles(self) -> bool:
        """True when the factors sum to the unclamped total and the score is its clamp."""
        summed = round(sum(f.signed_value for f in self.factors), 6)
        clamped = round(min(100.0, max(0.0, summed)), 2)
        return abs(summed - self.total_before_clamp) < 1e-6 and clamped == self.score


def explain_risk(
    path: AttackPath, assets: tuple[Asset, ...], assessment: PathRiskAssessment
) -> RiskExplanation:
    """Explain ``assessment`` (produced by ``RiskScorer.assess`` for ``path``) factor by factor."""
    by_id = {asset.asset_id: asset for asset in assets}
    path_assets = [by_id[asset_id] for asset_id in path.asset_ids]
    top = max(path_assets, key=lambda asset: _CRITICALITY_RANK[asset.criticality])
    relationship_types = [step.relationship_type for step in path.steps]
    weights = RiskScorer._RELATIONSHIP_VALUES
    average = sum(weights[kind] for kind in relationship_types) / len(relationship_types)
    breakdown = assessment.breakdown
    crown = path_assets[-1]

    credential_kinds = {RelationshipType.CREDENTIAL_ACCESS, RelationshipType.IAM_ASSUME_ROLE}
    credential_hits = [kind.value for kind in relationship_types if kind in credential_kinds]
    escape_hits = [kind for kind in relationship_types if kind is RelationshipType.CONTAINER_ESCAPE]

    factors = (
        RiskFactor(
            "Asset criticality",
            breakdown.criticality,
            25.0,
            f"Most critical asset on the path is `{top.name}` ({top.criticality.value}, "
            f"rank {_CRITICALITY_RANK[top.criticality]}/4): 25 × {_CRITICALITY_RANK[top.criticality]}/4.",
        ),
        RiskFactor(
            "Vulnerability severity (CVSS)",
            breakdown.cvss,
            30.0,
            "No scanner evidence was supplied for this scenario, so no CVSS contribution is "
            "claimed (0 of 30). Supplying vulnerabilities would raise this factor."
            if breakdown.cvss == 0.0
            else "Highest CVSS among vulnerabilities on the path nodes, scaled to 30.",
        ),
        RiskFactor(
            "Relationship severity",
            breakdown.relationship,
            20.0,
            f"Mean traversal weight over {len(relationship_types)} hops is {average:.3f} "
            f"({', '.join(kind.value for kind in relationship_types)}): 20 × {average:.3f}.",
        ),
        RiskFactor(
            "Crown-jewel reachability",
            breakdown.crown_jewel,
            15.0,
            f"The path ends at `{crown.name}`, a crown jewel or critical asset."
            if assessment.crown_jewel_reachable
            else "The path does not end at a crown jewel.",
        ),
        RiskFactor(
            "Credential exposure",
            breakdown.credential_exposure,
            5.0,
            f"Path includes credential-bearing step(s): {', '.join(credential_hits)}."
            if credential_hits
            else "No credential-access or role-assumption step on the path.",
        ),
        RiskFactor(
            "Container escape",
            breakdown.container_escape,
            5.0,
            "Path includes a CONTAINER_ESCAPE step."
            if escape_hits
            else "No container-escape step on the path.",
        ),
        RiskFactor(
            "Path length penalty",
            breakdown.path_length_penalty,
            0.0,
            f"{path.hop_count} hops: one point is deducted per hop beyond the first "
            "(longer chains are harder to complete).",
        ),
    )
    return RiskExplanation(
        score=assessment.score,
        total_before_clamp=round(breakdown.total_before_clamp, 6),
        factors=factors,
    )
