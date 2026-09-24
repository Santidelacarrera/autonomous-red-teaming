"""LangGraph state for the bounded, auditable simulation workflow."""

from __future__ import annotations

from operator import add
from typing import Annotated, NotRequired, TypedDict
from uuid import UUID

from art_sim.agents.models import (
    AttackPlan,
    CommandRecord,
    PlanStatus,
    ShadowEnvironmentScope,
    SimulationResult,
    SupervisorFinding,
)
from art_sim.domain.models import Asset, AttackPath
from art_sim.security.sanitizer import SanitizedTopologyContext


class AgentState(TypedDict):
    """Shared state with append-only audit fields and explicit planner lifecycle."""

    source_asset_id: UUID
    shadow_scope: ShadowEnvironmentScope
    attack_path: NotRequired[AttackPath]
    scoped_assets: NotRequired[tuple[Asset, ...]]
    planner_context: NotRequired[SanitizedTopologyContext]
    attack_plan: NotRequired[AttackPlan]
    plan_status: NotRequired[PlanStatus]
    replan_attempts: NotRequired[int]
    simulation_result: NotRequired[SimulationResult]
    command_history: Annotated[list[CommandRecord], add]
    supervisor_findings: Annotated[list[SupervisorFinding], add]
