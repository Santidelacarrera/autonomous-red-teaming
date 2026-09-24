"""Ports for replaceable planning and simulation adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from art_sim.agents.models import AttackPlan, SimulationResult, SupervisorFinding
from art_sim.security.sanitizer import SanitizedTopologyContext


class AttackPlanner(ABC):
    """Produces a candidate plan from a sanitized, bounded topology context."""

    @abstractmethod
    async def create_plan(
        self,
        context: SanitizedTopologyContext,
        findings: tuple[SupervisorFinding, ...],
    ) -> AttackPlan:
        """Return a plan that the independent supervisor must still audit."""


class ExecutionSimulator(ABC):
    """Runs a non-destructive simulation after supervisor approval."""

    @abstractmethod
    async def execute(self, plan: AttackPlan) -> SimulationResult:
        """Simulate the approved plan without contacting production systems."""
