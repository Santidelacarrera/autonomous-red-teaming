"""Typed contracts exchanged by the Phase 2 agent graph."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from art_sim.domain.models import Environment, RelationshipType


class SimulationAction(StrEnum):
    """Non-destructive actions allowed inside the shadow simulation."""

    OBSERVE_TOPOLOGY = "observe_topology"
    VALIDATE_TRUST = "validate_trust"
    SIMULATE_ROLE_ASSUMPTION = "simulate_role_assumption"
    SIMULATE_VULNERABILITY = "simulate_vulnerability"
    SIMULATE_LATERAL_MOVEMENT = "simulate_lateral_movement"


class PlanStatus(StrEnum):
    """Lifecycle status of a proposed attack plan."""

    DRAFT = "draft"
    APPROVED = "approved"
    REJECTED = "rejected"


class SimulationStatus(StrEnum):
    """Terminal result of the mock execution engine."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


class MitreTechnique(BaseModel):
    """A bounded MITRE ATT&CK reference used to explain a simulated hop."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    tactic: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)


class AttackPlanStep(BaseModel):
    """One safe simulation mapped to a graph edge and MITRE technique."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: RelationshipType
    technique: MitreTechnique
    action: SimulationAction
    simulation_only: bool = True


class AttackPlan(BaseModel):
    """Candidate path that must be approved before simulator execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: UUID = Field(default_factory=uuid4)
    source_asset_id: UUID
    target_asset_id: UUID
    environment: Environment
    scoped_asset_ids: tuple[UUID, ...] = Field(min_length=2, max_length=9)
    steps: tuple[AttackPlanStep, ...] = Field(min_length=1, max_length=8)
    simulation_only: bool = True
    status: PlanStatus = PlanStatus.DRAFT

    @model_validator(mode="after")
    def validate_chain(self) -> AttackPlan:
        """Require a contiguous, in-scope chain before a supervisor sees it."""
        if self.scoped_asset_ids[0] != self.source_asset_id:
            raise ValueError("scoped_asset_ids must start with source_asset_id")
        if self.scoped_asset_ids[-1] != self.target_asset_id:
            raise ValueError("scoped_asset_ids must end with target_asset_id")
        if len(self.scoped_asset_ids) != len(self.steps) + 1:
            raise ValueError("scoped_asset_ids must contain one more item than steps")
        for index, step in enumerate(self.steps):
            if (
                step.source_asset_id != self.scoped_asset_ids[index]
                or step.target_asset_id != self.scoped_asset_ids[index + 1]
            ):
                raise ValueError("attack-plan steps must form a contiguous chain")
        return self


class CommandRecord(BaseModel):
    """Auditable logical action issued by an agent; never a shell command."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent: str = Field(pattern=r"^[a-z_]{3,64}$")
    operation: str = Field(pattern=r"^[a-z_.]{3,128}$")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    outcome: str = Field(pattern=r"^(started|succeeded|rejected|blocked)$")
    detail: str = Field(min_length=1, max_length=256)


class SupervisorFinding(BaseModel):
    """A policy finding returned to the planner after a rejected proposal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(pattern=r"^[a-z_]{3,64}$")
    detail: str = Field(min_length=1, max_length=256)


class SimulationResult(BaseModel):
    """Evidence produced by the deliberately mock execution simulator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: SimulationStatus
    executed_actions: tuple[SimulationAction, ...]
    evidence: tuple[str, ...] = Field(max_length=32)
    simulated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ShadowEnvironmentScope(BaseModel):
    """Hard boundary enforced independently of planner intent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_id: UUID = Field(default_factory=uuid4)
    allowed_asset_ids: frozenset[UUID] = Field(min_length=2, max_length=1_000)
    required_environment: Environment = Environment.SHADOW
    max_replan_attempts: int = Field(default=2, ge=0, le=5)
