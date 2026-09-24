"""Transparent and configurable risk scoring for simulated attack paths."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from art_sim.domain.models import Asset, AttackPath, Criticality, RelationshipType, Vulnerability


class RiskScoringSettings(BaseModel):
    """Weights for a bounded 0-100 score, supplied through DI rather than globals.

    Default maximum contributions are criticality 25, CVSS 30, relation 20,
    crown-jewel reachability 15, credential exposure 5, and container escape 5.
    Each weight is a multiplier, allowing deployment-specific calibration.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    criticality_weight: float = Field(default=1.0, ge=0.0, le=5.0)
    cvss_weight: float = Field(default=1.0, ge=0.0, le=5.0)
    relation_weight: float = Field(default=1.0, ge=0.0, le=5.0)
    crown_jewel_weight: float = Field(default=1.0, ge=0.0, le=5.0)
    credential_exposure_weight: float = Field(default=1.0, ge=0.0, le=5.0)
    container_escape_weight: float = Field(default=1.0, ge=0.0, le=5.0)
    path_length_penalty: float = Field(default=1.0, ge=0.0, le=10.0)


class RiskBreakdown(BaseModel):
    """Named score components for auditability and executive reporting."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    criticality: float
    cvss: float
    relationship: float
    crown_jewel: float
    credential_exposure: float
    container_escape: float
    path_length_penalty: float

    @property
    def total_before_clamp(self) -> float:
        """Return the arithmetic total before the public score is bounded."""
        return (
            self.criticality
            + self.cvss
            + self.relationship
            + self.crown_jewel
            + self.credential_exposure
            + self.container_escape
            - self.path_length_penalty
        )


class PathRiskAssessment(BaseModel):
    """Risk result linked to one deterministic graph path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    score: float = Field(ge=0.0, le=100.0)
    breakdown: RiskBreakdown
    crown_jewel_reachable: bool


class RiskScorer:
    """Calculate reproducible path risk from typed topology and vulnerability evidence."""

    _CRITICALITY_VALUES: Mapping[Criticality, int] = {
        Criticality.LOW: 1,
        Criticality.MEDIUM: 2,
        Criticality.HIGH: 3,
        Criticality.CRITICAL: 4,
    }
    _RELATIONSHIP_VALUES: Mapping[RelationshipType, float] = {
        RelationshipType.NETWORK_REACHABLE: 0.35,
        RelationshipType.TRUSTS: 0.45,
        RelationshipType.ASSUMES_ROLE: 0.65,
        RelationshipType.EXPOSES: 0.55,
        RelationshipType.HOSTS: 0.40,
        RelationshipType.CONTAINER_ESCAPE: 1.0,
        RelationshipType.CREDENTIAL_ACCESS: 0.85,
        RelationshipType.IAM_ASSUME_ROLE: 0.90,
        RelationshipType.ACCESS: 0.70,
    }

    def __init__(self, settings: RiskScoringSettings | None = None) -> None:
        """Accept calibrated scoring settings while retaining conservative defaults."""
        self._settings = settings or RiskScoringSettings()

    def assess(
        self,
        path: AttackPath,
        assets: tuple[Asset, ...],
        vulnerabilities: tuple[Vulnerability, ...] = (),
    ) -> PathRiskAssessment:
        """Score a path using only data associated with its nodes and edges."""
        assets_by_id = {asset.asset_id: asset for asset in assets}
        path_assets = tuple(assets_by_id[asset_id] for asset_id in path.asset_ids if asset_id in assets_by_id)
        if len(path_assets) != len(path.asset_ids):
            raise ValueError("assets must cover every asset in the attack path")
        max_criticality = max(self._CRITICALITY_VALUES[asset.criticality] for asset in path_assets)
        relevant_vulnerabilities = tuple(
            vulnerability
            for vulnerability in vulnerabilities
            if vulnerability.affected_asset_id in set(path.asset_ids)
        )
        max_cvss = max((vulnerability.cvss_score for vulnerability in relevant_vulnerabilities), default=0.0)
        relation_average = sum(
            self._RELATIONSHIP_VALUES[step.relationship_type] for step in path.steps
        ) / len(path.steps)
        relationship_types = {step.relationship_type for step in path.steps}
        crown_jewel_reachable = path_assets[-1].is_crown_jewel or path_assets[-1].criticality is Criticality.CRITICAL
        breakdown = RiskBreakdown(
            criticality=25.0 * (max_criticality / 4.0) * self._settings.criticality_weight,
            cvss=30.0 * (max_cvss / 10.0) * self._settings.cvss_weight,
            relationship=20.0 * relation_average * self._settings.relation_weight,
            crown_jewel=15.0 * float(crown_jewel_reachable) * self._settings.crown_jewel_weight,
            credential_exposure=5.0
            * float(
                RelationshipType.CREDENTIAL_ACCESS in relationship_types
                or RelationshipType.IAM_ASSUME_ROLE in relationship_types
            )
            * self._settings.credential_exposure_weight,
            container_escape=5.0
            * float(RelationshipType.CONTAINER_ESCAPE in relationship_types)
            * self._settings.container_escape_weight,
            path_length_penalty=max(path.hop_count - 1, 0) * self._settings.path_length_penalty,
        )
        return PathRiskAssessment(
            score=round(min(100.0, max(0.0, breakdown.total_before_clamp)), 2),
            breakdown=breakdown,
            crown_jewel_reachable=crown_jewel_reachable,
        )
