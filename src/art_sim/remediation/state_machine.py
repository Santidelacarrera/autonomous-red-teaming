"""Explicit lifecycle invariants for a simulated remediation run."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from art_sim.remediation.models import ApprovalRecord, VerificationResult, VerificationStatus


class SimulationLifecycleState(StrEnum):
    """Allowed lifecycle states; no state implies an external infrastructure action."""

    CREATED = "created"
    ANALYZING = "analyzing"
    REMEDIATION_PENDING = "remediation_pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED_SIMULATED = "applied_simulated"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"


class RemediationLifecycle(BaseModel):
    """Validated state machine preventing impossible simulated remediation states."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: SimulationLifecycleState = SimulationLifecycleState.CREATED
    approval: ApprovalRecord | None = None
    verification: VerificationResult | None = None

    @model_validator(mode="after")
    def validate_invariants(self) -> RemediationLifecycle:
        """Require approval and verification evidence before dependent lifecycle states."""
        if self.state in {
            SimulationLifecycleState.APPROVED,
            SimulationLifecycleState.APPLIED_SIMULATED,
            SimulationLifecycleState.VERIFYING,
            SimulationLifecycleState.VERIFIED,
        } and (self.approval is None or self.approval.decision.value != "approved"):
            raise ValueError("approved lifecycle states require an approved approval record")
        if self.state is SimulationLifecycleState.VERIFIED and (
            self.verification is None or self.verification.status is not VerificationStatus.VERIFIED
        ):
            raise ValueError("verified lifecycle requires a verified verification result")
        return self

    def transition(
        self,
        target: SimulationLifecycleState,
        *,
        approval: ApprovalRecord | None = None,
        verification: VerificationResult | None = None,
    ) -> RemediationLifecycle:
        """Move only along the documented lifecycle transition graph."""
        allowed = {
            SimulationLifecycleState.CREATED: {SimulationLifecycleState.ANALYZING, SimulationLifecycleState.FAILED},
            SimulationLifecycleState.ANALYZING: {SimulationLifecycleState.REMEDIATION_PENDING, SimulationLifecycleState.FAILED},
            SimulationLifecycleState.REMEDIATION_PENDING: {SimulationLifecycleState.AWAITING_APPROVAL, SimulationLifecycleState.FAILED},
            SimulationLifecycleState.AWAITING_APPROVAL: {SimulationLifecycleState.APPROVED, SimulationLifecycleState.REJECTED},
            SimulationLifecycleState.APPROVED: {SimulationLifecycleState.APPLIED_SIMULATED, SimulationLifecycleState.FAILED},
            SimulationLifecycleState.APPLIED_SIMULATED: {SimulationLifecycleState.VERIFYING, SimulationLifecycleState.FAILED},
            SimulationLifecycleState.VERIFYING: {SimulationLifecycleState.VERIFIED, SimulationLifecycleState.FAILED},
            SimulationLifecycleState.REJECTED: set(),
            SimulationLifecycleState.VERIFIED: set(),
            SimulationLifecycleState.FAILED: set(),
        }
        if target not in allowed[self.state]:
            raise ValueError(f"Invalid lifecycle transition: {self.state.value} -> {target.value}")
        return RemediationLifecycle(
            state=target,
            approval=approval or self.approval,
            verification=verification or self.verification,
        )
