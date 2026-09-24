"""Independent scope enforcement for all candidate attack plans."""

from __future__ import annotations

from art_sim.agents.models import AttackPlan, PlanStatus, ShadowEnvironmentScope, SupervisorFinding
from art_sim.domain.exceptions import ScopeViolationError


class SupervisorAgent:
    """Audit a planner output without trusting its stated safety properties."""

    def audit(self, plan: AttackPlan, scope: ShadowEnvironmentScope) -> None:
        """Raise a stable domain error if any plan property crosses the shadow boundary."""
        violations: list[SupervisorFinding] = []
        if plan.environment is not scope.required_environment:
            violations.append(
                SupervisorFinding(code="environment_scope", detail="Plan environment is outside shadow scope.")
            )
        if not plan.simulation_only or any(not step.simulation_only for step in plan.steps):
            violations.append(
                SupervisorFinding(code="non_simulation_action", detail="Plan contains a non-simulation action.")
            )
        if not set(plan.scoped_asset_ids).issubset(scope.allowed_asset_ids):
            violations.append(
                SupervisorFinding(code="asset_scope", detail="Plan references assets outside the approved scope.")
            )
        if plan.status is not PlanStatus.DRAFT:
            violations.append(
                SupervisorFinding(code="invalid_plan_state", detail="Only draft plans may enter review."))
        if violations:
            raise ScopeViolationError(violations)
