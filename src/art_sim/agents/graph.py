"""LangGraph composition root for the Phase 2 bounded attack simulation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from art_sim.agents.models import CommandRecord, PlanStatus
from art_sim.agents.ports import AttackPlanner, ExecutionSimulator
from art_sim.agents.recon import ReconAgent
from art_sim.agents.simulator import MockExecutionSimulator
from art_sim.agents.state import AgentState
from art_sim.agents.supervisor import SupervisorAgent
from art_sim.domain.exceptions import ScopeViolationError
from art_sim.observability.telemetry import Tracer


class AttackSimulationGraph:
    """Compose bounded recon, planning, supervision, and mock execution nodes."""

    def __init__(
        self,
        recon_agent: ReconAgent,
        planner: AttackPlanner,
        supervisor: SupervisorAgent,
        simulator: ExecutionSimulator | None = None,
        tracer: Tracer | None = None,
    ) -> None:
        """Inject every collaborator so the graph has no hidden global dependencies."""
        self._recon_agent = recon_agent
        self._planner = planner
        self._supervisor = supervisor
        self._simulator = simulator or MockExecutionSimulator()
        self._tracer = tracer

    def compile(
        self,
        checkpointer: BaseCheckpointSaver[Any] | None = None,
    ) -> CompiledStateGraph[AgentState, None, AgentState, AgentState]:
        """Compile conditional routing: reject/replan, approve/simulate, or stop safely."""
        builder = StateGraph(AgentState)
        builder.add_node("recon", self._recon_node)
        builder.add_node("planner", self._planner_node)
        builder.add_node("supervisor", self._supervisor_node)
        builder.add_node("simulator", self._simulator_node)
        builder.add_edge(START, "recon")
        builder.add_edge("recon", "planner")
        builder.add_edge("planner", "supervisor")
        builder.add_conditional_edges(
            "supervisor",
            self._route_after_supervisor,
            {"planner": "planner", "simulator": "simulator", "end": END},
        )
        builder.add_edge("simulator", END)
        return builder.compile(checkpointer=checkpointer)

    async def _recon_node(self, state: AgentState) -> dict[str, object]:
        """Get the bounded candidate path and sanitized planner context."""
        started_at = datetime.now(UTC)
        try:
            path, context, assets = await self._recon_agent.discover(
                state["source_asset_id"], state["shadow_scope"].allowed_asset_ids
            )
            result: dict[str, object] = {
                "attack_path": path,
                "scoped_assets": assets,
                "planner_context": context,
                "command_history": [
                    CommandRecord(
                        agent="recon_agent",
                        operation="graph.shortest_path",
                        outcome="succeeded",
                        detail="Retrieved a bounded, shadow-only topology path.",
                    )
                ],
            }
        except Exception as error:
            self._record_telemetry("recon_agent", "recon", started_at, state, {}, error)
            raise
        self._record_telemetry("recon_agent", "recon", started_at, state, result)
        return result

    async def _planner_node(self, state: AgentState) -> dict[str, object]:
        """Create a candidate MITRE chain from sanitized topology only."""
        started_at = datetime.now(UTC)
        try:
            context = state["planner_context"]
            plan = await self._planner.create_plan(context, tuple(state.get("supervisor_findings", [])))
            result: dict[str, object] = {
                "attack_plan": plan,
                "plan_status": PlanStatus.DRAFT,
                "command_history": [
                    CommandRecord(
                        agent="planner_agent",
                        operation="plan.generate_mitre_chain",
                        outcome="succeeded",
                        detail="Generated a simulation-only candidate plan.",
                    )
                ],
            }
        except Exception as error:
            self._record_telemetry("planner_agent", "planner", started_at, state, {}, error)
            raise
        self._record_telemetry("planner_agent", "planner", started_at, state, result)
        return result

    async def _supervisor_node(self, state: AgentState) -> dict[str, object]:
        """Audit the plan and convert a policy exception into controlled replan state."""
        started_at = datetime.now(UTC)
        plan = state["attack_plan"]
        try:
            self._supervisor.audit(plan, state["shadow_scope"])
        except ScopeViolationError as error:
            result: dict[str, object] = {
                "attack_plan": plan.model_copy(update={"status": PlanStatus.REJECTED}),
                "plan_status": PlanStatus.REJECTED,
                "replan_attempts": state.get("replan_attempts", 0) + 1,
                "supervisor_findings": list(error.findings),
                "command_history": [
                    CommandRecord(
                        agent="supervisor_agent",
                        operation="scope.audit",
                        outcome="rejected",
                        detail="Supervisor rejected a plan outside policy constraints.",
                    )
                ],
            }
            self._record_telemetry("supervisor_agent", "supervisor", started_at, state, result, rejected=True)
            return result
        result = {
            "attack_plan": plan.model_copy(update={"status": PlanStatus.APPROVED}),
            "plan_status": PlanStatus.APPROVED,
            "command_history": [
                CommandRecord(
                    agent="supervisor_agent",
                    operation="scope.audit",
                    outcome="succeeded",
                    detail="Supervisor approved the shadow-only plan.",
                )
            ],
        }
        self._record_telemetry("supervisor_agent", "supervisor", started_at, state, result)
        return result

    async def _simulator_node(self, state: AgentState) -> dict[str, object]:
        """Execute only an independently approved plan using the mock adapter."""
        started_at = datetime.now(UTC)
        try:
            simulation = await self._simulator.execute(state["attack_plan"])
            result: dict[str, object] = {
                "simulation_result": simulation,
                "command_history": [
                    CommandRecord(
                        agent="execution_simulator",
                        operation="simulation.execute",
                        outcome="succeeded" if simulation.status.value == "succeeded" else "blocked",
                        detail="Mock execution completed without external side effects.",
                    )
                ],
            }
        except Exception as error:
            self._record_telemetry("execution_simulator", "simulator", started_at, state, {}, error)
            raise
        self._record_telemetry("execution_simulator", "simulator", started_at, state, result)
        return result

    def _record_telemetry(
        self,
        agent_name: str,
        node_name: str,
        started_at: datetime,
        state: AgentState,
        result: dict[str, object],
        error: Exception | None = None,
        rejected: bool = False,
    ) -> None:
        """Emit non-sensitive execution metadata when a tracer is provided through DI."""
        if self._tracer is None:
            return
        self._tracer.record_agent_event(
            agent_name=agent_name,
            node_name=node_name,
            started_at=started_at,
            input_size=len(repr(state)),
            output_size=len(repr(result)),
            status="failed" if error else "rejected" if rejected else "succeeded",
            error=str(error)[:256] if error else None,
        )

    @staticmethod
    def _route_after_supervisor(state: AgentState) -> Literal["planner", "simulator", "end"]:
        """Route rejected plans to replan only while the bounded retry budget remains."""
        if state["plan_status"] is PlanStatus.APPROVED:
            return "simulator"
        if state.get("replan_attempts", 0) <= state["shadow_scope"].max_replan_attempts:
            return "planner"
        return "end"
