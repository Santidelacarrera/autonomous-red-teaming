"""Durable LangGraph orchestration over existing Shadow simulation components."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, cast

from langchain_core.runnables.config import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from pydantic import BaseModel, ConfigDict

from art_sim.agents.graph import AttackSimulationGraph
from art_sim.agents.models import ShadowEnvironmentScope
from art_sim.agents.planner import MitrePathPlanner
from art_sim.agents.recon import ReconAgent
from art_sim.agents.state import AgentState
from art_sim.agents.supervisor import SupervisorAgent
from art_sim.attack.risk import RiskScorer
from art_sim.blast_radius.calculator import BlastRadiusCalculator
from art_sim.domain.exceptions import ApprovalRequiredError, WorkerStateError
from art_sim.observability.telemetry import Tracer
from art_sim.platform.models import SimulationRun
from art_sim.remediation.agent import RemediationAgent
from art_sim.remediation.approval import HumanApprovalWorkflow, RemediationFlowState
from art_sim.remediation.generator import PolicyRemediationGenerator
from art_sim.remediation.models import (
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStatus,
    RemediationRequest,
    VerificationResult,
)
from art_sim.remediation.normalization import RemediationPlanner
from art_sim.remediation.preapproval import CountermeasurePreApprovalPolicy
from art_sim.remediation.verification import RemediationVerifier
from art_sim.reporting.markdown import MarkdownReportRenderer
from art_sim.reporting.models import SecuritySimulationReport
from art_sim.security.sanitizer import PromptInjectionSanitizer
from art_sim.worker.models import SimulationArtifacts, SimulationReview, SimulationScenario
from art_sim.worker.shadow import ShadowGraphRepository


class WorkflowOutcomeStatus(StrEnum):
    """Worker-relevant outcome of one start or resume invocation."""

    WAITING_APPROVAL = "waiting_approval"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"


class WorkflowOutcome(BaseModel):
    """Typed workflow result; final artifacts exist only for successful completion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: WorkflowOutcomeStatus
    artifacts: SimulationArtifacts | None = None
    review: SimulationReview | None = None


class DurableSimulationWorkflow:
    """Run and recover the existing LangGraph plus deterministic analysis pipeline."""

    def __init__(
        self,
        checkpointer: BaseCheckpointSaver[Any],
        approval_secret: bytes,
    ) -> None:
        if len(approval_secret) < 32:
            raise ValueError("approval_secret must contain at least 32 bytes")
        self._checkpointer = checkpointer
        self._approval_secret = approval_secret
        self._risk = RiskScorer()
        self._blast = BlastRadiusCalculator()
        self._remediation = RemediationPlanner()
        self._verifier = RemediationVerifier()
        self._artifact_agent = RemediationAgent(PolicyRemediationGenerator())
        self._preapproval = CountermeasurePreApprovalPolicy()
        self._renderer = MarkdownReportRenderer()

    async def execute(
        self,
        run: SimulationRun,
        scenario: SimulationScenario,
        tracer: Tracer,
    ) -> WorkflowOutcome:
        """Start or resume by `run_id`; every graph operation remains simulation-only."""
        state = await self._attack_state(run, scenario, tracer)
        path = state.get("attack_path")
        plan = state.get("attack_plan")
        simulation = state.get("simulation_result")
        context = state.get("planner_context")
        if path is None or plan is None or simulation is None or context is None:
            raise WorkerStateError("Attack workflow did not produce required typed results")

        assessment = self._risk.assess(path, scenario.graph.assets)
        blast_radius = self._blast.calculate(scenario.graph, scenario.source_asset_id)
        remediation = self._remediation.propose(path, assessment)
        target = next(
            (asset for asset in context.assets if asset.asset_id == plan.target_asset_id),
            None,
        )
        if target is None:
            raise WorkerStateError("Attack workflow target is missing from sanitized context")
        remediation_artifact = await self._artifact_agent.generate(
            RemediationRequest(plan=plan, simulation=simulation, target=target)
        )
        verification_preview = self._verifier.verify(
            scenario.graph,
            scenario.source_asset_id,
            remediation,
        )
        automated_preapproval = self._preapproval.evaluate(
            remediation,
            remediation_artifact,
            verification_preview,
        )
        review = SimulationReview(
            run_id=run.run_id,
            scenario_id=run.scenario_id,
            workflow_version=run.workflow_version,
            graph_version=scenario.graph_version,
            attack_path=path,
            risk=assessment,
            blast_radius=blast_radius,
            remediation=remediation,
            remediation_artifact=remediation_artifact,
            verification_preview=verification_preview,
            automated_preapproval=automated_preapproval,
        )

        approval: ApprovalRecord | None = None
        if scenario.requires_approval:
            approval_workflow = HumanApprovalWorkflow(
                self._verifier,
                checkpointer=self._checkpointer,
                approval_secret=self._approval_secret,
                checkpoint_namespace="remediation",
            )
            current = await approval_workflow.current(run.run_id)
            if run.approval_status is ApprovalStatus.PENDING:
                if current is None:
                    await approval_workflow.start(
                        RemediationFlowState(
                            run_id=run.run_id,
                            source_asset_id=scenario.source_asset_id,
                            simulated_graph=scenario.graph,
                            remediation=remediation,
                            risk_score=assessment.score,
                            approval_required=True,
                            approval_status=ApprovalStatus.PENDING,
                        )
                    )
                elif current.get("approval_status") is not ApprovalStatus.PENDING:
                    raise WorkerStateError("Approval checkpoint conflicts with operational state")
                return WorkflowOutcome(
                    status=WorkflowOutcomeStatus.WAITING_APPROVAL,
                    review=review,
                )

            if run.approval_actor is None:
                raise ApprovalRequiredError("Recorded approval is missing its verified actor")
            if run.approval_reason is None:
                raise ApprovalRequiredError("Recorded approval is missing its review reason")
            decision = (
                ApprovalDecision.APPROVED
                if run.approval_status is ApprovalStatus.APPROVED
                else ApprovalDecision.REJECTED
            )
            final = await approval_workflow.resume_recorded_decision(
                run.run_id,
                decision=decision,
                operator=run.approval_actor,
                reason=run.approval_reason,
            )
            approval_value = final.get("approval_record")
            if not isinstance(approval_value, ApprovalRecord):
                raise WorkerStateError("Approval workflow did not produce an audit record")
            approval = approval_value
            if decision is ApprovalDecision.REJECTED:
                return WorkflowOutcome(status=WorkflowOutcomeStatus.REJECTED)
            verification_value = final.get("verification_result")
            if not isinstance(verification_value, VerificationResult):
                raise WorkerStateError("Approval workflow did not produce verification")
            verification = verification_value
        else:
            verification = verification_preview

        report_model = SecuritySimulationReport(
            run_id=run.run_id,
            total_assets=len(scenario.graph.assets),
            total_critical_assets=sum(
                asset.criticality.value == "critical" for asset in scenario.graph.assets
            ),
            attack_paths=(path,),
            assessments=(assessment,),
            blast_radius_before=blast_radius,
            remediation=remediation,
            approval=approval,
            verification=verification,
            telemetry=tuple(tracer.agent_events),
            evidence=simulation.evidence,
        )
        artifacts = SimulationArtifacts(
            run_id=run.run_id,
            scenario_id=run.scenario_id,
            workflow_version=run.workflow_version,
            graph_version=scenario.graph_version,
            attack_paths=(path,),
            risk=assessment,
            blast_radius=blast_radius,
            remediations=(remediation,),
            remediation_artifacts=(remediation_artifact,),
            approval=approval,
            verification=verification,
            report_markdown=self._renderer.render(report_model),
            trace_id=tracer.trace_id,
        )
        return WorkflowOutcome(status=WorkflowOutcomeStatus.SUCCEEDED, artifacts=artifacts)

    async def _attack_state(
        self,
        run: SimulationRun,
        scenario: SimulationScenario,
        tracer: Tracer,
    ) -> AgentState:
        repository = ShadowGraphRepository(scenario.graph)
        graph = AttackSimulationGraph(
            ReconAgent(repository, PromptInjectionSanitizer()),
            MitrePathPlanner(),
            SupervisorAgent(),
            tracer=tracer,
        ).compile(self._checkpointer)
        config: RunnableConfig = {
            "configurable": {
                "thread_id": f"{run.run_id}:attack",
            }
        }
        snapshot = await graph.aget_state(config)
        if snapshot.values:
            values = await graph.ainvoke(None, config) if snapshot.next else snapshot.values
        else:
            initial: AgentState = {
                "source_asset_id": scenario.source_asset_id,
                "shadow_scope": ShadowEnvironmentScope(
                    allowed_asset_ids=frozenset(
                        asset.asset_id for asset in scenario.graph.assets
                    )
                ),
                "command_history": [],
                "supervisor_findings": [],
            }
            values = await graph.ainvoke(initial, config)
        return cast(AgentState, values)
