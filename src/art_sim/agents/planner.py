"""Deterministic MITRE mapper used until an LLM planner is introduced safely."""

from __future__ import annotations

from typing import ClassVar

from art_sim.agents.models import (
    AttackPlan,
    AttackPlanStep,
    MitreTechnique,
    SimulationAction,
    SupervisorFinding,
)
from art_sim.agents.ports import AttackPlanner
from art_sim.domain.models import Environment, RelationshipType
from art_sim.security.sanitizer import SanitizedTopologyContext


class MitrePathPlanner(AttackPlanner):
    """Generate a safe, explainable plan directly from a sanitized graph path."""

    _TECHNIQUES: ClassVar[dict[RelationshipType, tuple[MitreTechnique, SimulationAction]]] = {
        RelationshipType.NETWORK_REACHABLE: (
            MitreTechnique(
                technique_id="T1046", tactic="discovery", name="Network Service Discovery"
            ),
            SimulationAction.OBSERVE_TOPOLOGY,
        ),
        RelationshipType.TRUSTS: (
            MitreTechnique(technique_id="T1078", tactic="defense_evasion", name="Valid Accounts"),
            SimulationAction.VALIDATE_TRUST,
        ),
        RelationshipType.ASSUMES_ROLE: (
            MitreTechnique(technique_id="T1078", tactic="privilege_escalation", name="Valid Accounts"),
            SimulationAction.SIMULATE_ROLE_ASSUMPTION,
        ),
        RelationshipType.EXPOSES: (
            MitreTechnique(
                technique_id="T1190", tactic="initial_access", name="Exploit Public-Facing Application"
            ),
            SimulationAction.SIMULATE_VULNERABILITY,
        ),
        RelationshipType.HOSTS: (
            MitreTechnique(technique_id="T1021", tactic="lateral_movement", name="Remote Services"),
            SimulationAction.SIMULATE_LATERAL_MOVEMENT,
        ),
    }

    async def create_plan(
        self,
        context: SanitizedTopologyContext,
        findings: tuple[SupervisorFinding, ...],
    ) -> AttackPlan:
        """Map every graph hop to an allow-listed MITRE technique and mock action."""
        del findings  # The deterministic baseline always emits the least-privilege plan.
        steps = tuple(
            AttackPlanStep(
                source_asset_id=hop.source_asset_id,
                target_asset_id=hop.target_asset_id,
                relationship_type=hop.relationship_type,
                technique=self._TECHNIQUES[hop.relationship_type][0],
                action=self._TECHNIQUES[hop.relationship_type][1],
            )
            for hop in context.hops
        )
        return AttackPlan(
            source_asset_id=context.source_asset_id,
            target_asset_id=context.target_asset_id,
            environment=Environment.SHADOW,
            scoped_asset_ids=tuple(asset.asset_id for asset in context.assets),
            steps=steps,
        )
