"""Typed reporting DTOs assembled from actual simulation artifacts only."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from art_sim.attack.risk import PathRiskAssessment
from art_sim.blast_radius.calculator import BlastRadiusResult
from art_sim.domain.models import AttackPath, Vulnerability
from art_sim.observability.telemetry import AgentTelemetry
from art_sim.remediation.models import ApprovalRecord, NormalizedRemediation, VerificationResult


class SecuritySimulationReport(BaseModel):
    """Complete report data; values must originate in analysis or recorded workflow state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: UUID = Field(default_factory=uuid4)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    run_id: UUID
    total_assets: int = Field(ge=0)
    total_critical_assets: int = Field(ge=0)
    attack_paths: tuple[AttackPath, ...]
    assessments: tuple[PathRiskAssessment, ...]
    vulnerabilities: tuple[Vulnerability, ...] = ()
    blast_radius_before: BlastRadiusResult
    remediation: NormalizedRemediation | None = None
    approval: ApprovalRecord | None = None
    verification: VerificationResult | None = None
    telemetry: tuple[AgentTelemetry, ...] = ()
    evidence: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
