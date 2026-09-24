"""Typed, serializable inputs and final artifacts for durable Shadow workflows."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from art_sim.attack.risk import PathRiskAssessment
from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.blast_radius.calculator import BlastRadiusResult
from art_sim.domain.models import AttackPath, Environment
from art_sim.remediation.models import (
    ApprovalRecord,
    NormalizedRemediation,
    RemediationArtifact,
    VerificationResult,
)


class SimulationScenario(BaseModel):
    """Operator-configured Shadow fixture; API callers can select only its identifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")
    graph_version: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    source_asset_id: UUID
    graph: SimulatedAttackGraph
    requires_approval: bool = True

    @model_validator(mode="after")
    def require_shadow_graph(self) -> SimulationScenario:
        """Reject scenarios containing any non-Shadow asset or an unknown source."""
        if self.source_asset_id not in {asset.asset_id for asset in self.graph.assets}:
            raise ValueError("Scenario source asset must exist in its Shadow graph")
        if any(asset.environment is not Environment.SHADOW for asset in self.graph.assets):
            raise ValueError("Simulation scenarios may contain only Shadow assets")
        return self


class SimulationArtifacts(BaseModel):
    """Immutable final result persisted once and served without regeneration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")
    workflow_version: str = Field(min_length=1, max_length=64)
    graph_version: str = Field(min_length=1, max_length=128)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    attack_paths: tuple[AttackPath, ...] = Field(min_length=1, max_length=32)
    risk: PathRiskAssessment
    blast_radius: BlastRadiusResult
    remediations: tuple[NormalizedRemediation, ...] = Field(min_length=1, max_length=32)
    remediation_artifacts: tuple[RemediationArtifact, ...] = Field(min_length=1, max_length=32)
    approval: ApprovalRecord | None = None
    verification: VerificationResult
    report_markdown: str = Field(min_length=1, max_length=200_000)
    trace_id: UUID
