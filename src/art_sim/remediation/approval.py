"""LangGraph human-approval workflow with checkpointed pause and explicit resume."""

from __future__ import annotations

import asyncio
import hmac
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Literal, NotRequired, TypedDict
from uuid import UUID

from langchain_core.runnables.config import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.domain.exceptions import ApprovalRequiredError, ConfigurationError
from art_sim.remediation.models import (
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStatus,
    NormalizedRemediation,
    VerificationResult,
)
from art_sim.remediation.state_machine import RemediationLifecycle, SimulationLifecycleState
from art_sim.remediation.verification import RemediationVerifier


class RemediationFlowState(TypedDict):
    """Checkpointed state required for pause, inspect, decision, resume, and verification."""

    run_id: UUID
    source_asset_id: UUID
    simulated_graph: SimulatedAttackGraph
    remediation: NormalizedRemediation
    risk_score: float
    approval_required: bool
    approval_status: ApprovalStatus
    approval_decision: NotRequired[ApprovalDecision]
    approved_by: NotRequired[str]
    approval_reason: NotRequired[str]
    approval_record: NotRequired[ApprovalRecord]
    approval_proof: NotRequired[str]
    verification_result: NotRequired[VerificationResult]
    lifecycle: NotRequired[RemediationLifecycle]


class HumanApprovalWorkflow:
    """Pause before simulated remediation verification until an operator records a decision."""

    def __init__(
        self,
        verifier: RemediationVerifier,
        checkpointer: BaseCheckpointSaver[Any] | None = None,
        approval_secret: bytes | None = None,
        checkpoint_namespace: str = "remediation",
    ) -> None:
        """Inject verifier, checkpoint store, and stable production signing material.

        The secret is mandatory: missing signing material fails closed. A deployment
        that resumes workflow checkpoints across process boundaries must inject the
        same secret from its secret manager on every replica.
        """
        if approval_secret is None:
            raise ConfigurationError("approval_secret is required for human approval verification")
        if len(approval_secret) < 32:
            raise ValueError("approval_secret must contain at least 32 bytes")
        self._verifier = verifier
        self._checkpointer = checkpointer or MemorySaver()
        self._approval_secret = approval_secret
        self._checkpoint_namespace = checkpoint_namespace
        self._decision_locks: dict[UUID, asyncio.Lock] = {}
        self._graph = self._compile()

    @property
    def graph(self) -> CompiledStateGraph[RemediationFlowState, None, RemediationFlowState, RemediationFlowState]:
        """Expose the compiled graph for inspection or supported LangGraph operations."""
        return self._graph

    async def start(self, state: RemediationFlowState) -> dict[str, object]:
        """Run to the checkpoint immediately before the approval node."""
        return await self._graph.ainvoke(state, self._config(state["run_id"]))

    async def decide(
        self,
        run_id: UUID,
        *,
        decision: ApprovalDecision,
        operator: str,
        reason: str,
    ) -> dict[str, object]:
        """Persist a human decision then resume the checkpointed graph exactly once."""
        if not operator.strip() or not reason.strip():
            raise ApprovalRequiredError("Approval operator and reason are required")
        lock = self._decision_locks.setdefault(run_id, asyncio.Lock())
        async with lock:
            config = self._config(run_id)
            current = await self._graph.aget_state(config)
            current_values = current.values
            if current_values.get("approval_status") is not ApprovalStatus.PENDING:
                raise ApprovalRequiredError("Only a pending remediation can receive an approval decision")
            await self._graph.aupdate_state(
                config,
                {"approval_decision": decision, "approved_by": operator, "approval_reason": reason},
            )
            return await self._graph.ainvoke(None, config)

    async def resume_recorded_decision(
        self,
        run_id: UUID,
        *,
        decision: ApprovalDecision,
        operator: str,
        reason: str,
    ) -> dict[str, object]:
        """Resume a durable API decision or recover its already completed checkpoint.

        The operational-store CAS is the authority for accepting a decision. This
        method remains idempotent only for the exact same recorded decision and actor.
        """
        if not operator.strip() or not reason.strip():
            raise ApprovalRequiredError("Approval operator and reason are required")
        config = self._config(run_id)
        current = await self._graph.aget_state(config)
        values = current.values
        status = values.get("approval_status")
        if status is ApprovalStatus.PENDING:
            await self._graph.aupdate_state(
                config,
                {
                    "approval_decision": decision,
                    "approved_by": operator,
                    "approval_reason": reason,
                },
            )
            return await self._graph.ainvoke(None, config)
        record = values.get("approval_record")
        proof = values.get("approval_proof")
        if (
            isinstance(record, ApprovalRecord)
            and isinstance(proof, str)
            and record.decision is decision
            and record.operator == operator
            and hmac.compare_digest(proof, self._approval_proof(run_id, record))
        ):
            return dict(values)
        raise ApprovalRequiredError("Recorded approval does not match the workflow checkpoint")

    async def current(self, run_id: UUID) -> dict[str, object] | None:
        """Return a checkpoint snapshot when this workflow has already started."""
        values = (await self._graph.aget_state(self._config(run_id))).values
        return dict(values) if values else None

    def _compile(self) -> CompiledStateGraph[RemediationFlowState, None, RemediationFlowState, RemediationFlowState]:
        """Compile a graph that interrupts before the human-decision node."""
        builder = StateGraph(RemediationFlowState)
        builder.add_node("prepare", self._prepare)
        builder.add_node("approval", self._approval)
        builder.add_node("verification", self._verification)
        builder.add_edge(START, "prepare")
        builder.add_edge("prepare", "approval")
        builder.add_conditional_edges("approval", self._route, {"verification": "verification", "end": END})
        builder.add_edge("verification", END)
        return builder.compile(checkpointer=self._checkpointer, interrupt_before=["approval"])

    @staticmethod
    async def _prepare(state: RemediationFlowState) -> dict[str, object]:
        """Record that all sensitive simulation changes require a human decision."""
        lifecycle = (
            RemediationLifecycle()
            .transition(SimulationLifecycleState.ANALYZING)
            .transition(SimulationLifecycleState.REMEDIATION_PENDING)
            .transition(SimulationLifecycleState.AWAITING_APPROVAL)
        )
        return {"approval_required": True, "approval_status": ApprovalStatus.PENDING, "lifecycle": lifecycle}

    async def _approval(self, state: RemediationFlowState) -> dict[str, object]:
        """Create immutable approval audit evidence from the externally supplied decision."""
        decision = state.get("approval_decision")
        operator = state.get("approved_by")
        reason = state.get("approval_reason")
        if decision is None or not operator or not reason:
            raise ApprovalRequiredError("Human approval decision, operator, and reason are required")
        record = ApprovalRecord(
            remediation_id=state["remediation"].remediation_id,
            operator=operator,
            decision=decision,
            risk_score=state["risk_score"],
            reason=reason,
            decided_at=datetime.now(UTC),
        )
        lifecycle = state.get("lifecycle")
        if lifecycle is None or lifecycle.state is not SimulationLifecycleState.AWAITING_APPROVAL:
            raise ApprovalRequiredError("Approval is only valid from the awaiting-approval lifecycle state")
        approval_status = ApprovalStatus.APPROVED if decision is ApprovalDecision.APPROVED else ApprovalStatus.REJECTED
        return {
            "approval_status": approval_status,
            "approval_record": record,
            "approval_proof": self._approval_proof(state["run_id"], record),
            "lifecycle": lifecycle.transition(
                SimulationLifecycleState.APPROVED
                if decision is ApprovalDecision.APPROVED
                else SimulationLifecycleState.REJECTED,
                approval=record,
            ),
        }

    def _verification(self, state: RemediationFlowState) -> dict[str, object]:
        """Verify only after a recorded approval, against a simulated graph copy."""
        if state["approval_status"] is not ApprovalStatus.APPROVED:
            raise ApprovalRequiredError("Verification requires approved remediation")
        record = state.get("approval_record")
        proof = state.get("approval_proof")
        if record is None or proof is None or record.decision is not ApprovalDecision.APPROVED:
            raise ApprovalRequiredError("Verification requires a signed approval record")
        if not hmac.compare_digest(proof, self._approval_proof(state["run_id"], record)):
            raise ApprovalRequiredError("Approval proof is invalid for this remediation workflow")
        lifecycle = state.get("lifecycle")
        if lifecycle is None or lifecycle.state is not SimulationLifecycleState.APPROVED:
            raise ApprovalRequiredError("Verification requires an approved lifecycle state")
        result = self._verifier.verify(state["simulated_graph"], state["source_asset_id"], state["remediation"])
        verifying = lifecycle.transition(SimulationLifecycleState.APPLIED_SIMULATED).transition(
            SimulationLifecycleState.VERIFYING
        )
        terminal_state = (
            SimulationLifecycleState.VERIFIED
            if result.status.value == "verified"
            else SimulationLifecycleState.FAILED
        )
        return {
            "verification_result": result,
            "lifecycle": verifying.transition(terminal_state, verification=result),
        }

    @staticmethod
    def _route(state: RemediationFlowState) -> Literal["verification", "end"]:
        """Only approved decisions proceed; rejected candidates stop without a simulated apply."""
        return "verification" if state["approval_status"] is ApprovalStatus.APPROVED else "end"

    def _config(self, run_id: UUID) -> RunnableConfig:
        """Return the stable LangGraph checkpoint key for one remediation workflow run."""
        return {
            "configurable": {
                "thread_id": f"{run_id}:{self._checkpoint_namespace}",
            }
        }

    def _approval_proof(self, run_id: UUID, record: ApprovalRecord) -> str:
        """Bind approval evidence to a workflow and remediation without storing a secret in state."""
        material = ":".join(
            (
                str(run_id),
                str(record.remediation_id),
                record.operator,
                record.decision.value,
                record.decided_at.isoformat(),
            )
        )
        return hmac.new(self._approval_secret, material.encode("utf-8"), sha256).hexdigest()
