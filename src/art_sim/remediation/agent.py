"""Remediation agent that accepts only successful, supervised Shadow simulations."""

from __future__ import annotations

from art_sim.agents.models import PlanStatus, SimulationAction, SimulationStatus
from art_sim.domain.exceptions import RemediationEligibilityError
from art_sim.domain.models import Environment
from art_sim.remediation.models import (
    RemediationArtifact,
    RemediationKind,
    RemediationPrompt,
    RemediationRequest,
)
from art_sim.remediation.ports import RemediationGenerator


class RemediationAgent:
    """Build an injection-resistant structured prompt and generate a policy candidate."""

    _CONSTRAINTS = (
        "Generate declarative infrastructure-as-code only.",
        "Target Shadow environment only; never include production resources.",
        "Use deterministic names and an explicit idempotency marker.",
        "Do not attach policies, execute commands, or apply manifests.",
    )

    def __init__(self, generator: RemediationGenerator) -> None:
        """Inject a renderer; a future LLM adapter must remain behind this boundary."""
        self._generator = generator

    async def generate(self, request: RemediationRequest) -> RemediationArtifact:
        """Generate a patch only after scope approval and successful mock simulation."""
        self._validate_eligibility(request)
        return await self._generator.generate(self._build_prompt(request))

    @staticmethod
    def _validate_eligibility(request: RemediationRequest) -> None:
        """Fail closed before remediation if any upstream safety guarantee is absent."""
        if request.plan.status is not PlanStatus.APPROVED:
            raise RemediationEligibilityError("Remediation requires an independently approved attack plan")
        if request.simulation.status is not SimulationStatus.SUCCEEDED:
            raise RemediationEligibilityError("Remediation requires a successful shadow simulation")
        if request.plan.environment is not Environment.SHADOW or request.target.environment != "shadow":
            raise RemediationEligibilityError("Remediation is limited to the Shadow environment")
        if not request.plan.simulation_only:
            raise RemediationEligibilityError("Remediation requires a simulation-only attack plan")

    @classmethod
    def _build_prompt(cls, request: RemediationRequest) -> RemediationPrompt:
        """Project UUIDs and enums only; evidence text is never included in a prompt."""
        actions = tuple(step.action for step in request.plan.steps)
        kind = (
            RemediationKind.AWS_IAM_POLICY
            if SimulationAction.SIMULATE_ROLE_ASSUMPTION in actions
            else RemediationKind.KUBERNETES_NETWORK_POLICY
        )
        return RemediationPrompt(
            plan_id=request.plan.plan_id,
            target_asset_id=request.target.asset_id,
            target_asset_type=request.target.asset_type.value,
            simulated_actions=actions,
            remediation_kind=kind,
            constraints=cls._CONSTRAINTS,
        )
