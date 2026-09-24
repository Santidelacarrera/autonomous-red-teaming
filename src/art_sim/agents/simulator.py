"""Safe mock simulator; it performs no exploit, shell, network, or cloud action."""

from __future__ import annotations

from art_sim.agents.models import AttackPlan, SimulationResult, SimulationStatus
from art_sim.agents.ports import ExecutionSimulator


class MockExecutionSimulator(ExecutionSimulator):
    """Produce reproducible evidence for an approved, simulation-only attack plan."""

    async def execute(self, plan: AttackPlan) -> SimulationResult:
        """Return synthetic evidence without interacting with any external target."""
        if not plan.simulation_only:
            return SimulationResult(
                status=SimulationStatus.BLOCKED,
                executed_actions=(),
                evidence=("Execution blocked: plan is not simulation-only.",),
            )
        return SimulationResult(
            status=SimulationStatus.SUCCEEDED,
            executed_actions=tuple(step.action for step in plan.steps),
            evidence=(
                f"Simulated {len(plan.steps)} bounded graph transitions.",
                f"Target crown-jewel candidate: {plan.target_asset_id}.",
            ),
        )
