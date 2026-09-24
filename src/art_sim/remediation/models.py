"""Safe, typed remediation contracts for generated policy candidates."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from art_sim.agents.models import AttackPlan, SimulationAction, SimulationResult
from art_sim.blast_radius.calculator import BlastRadiusResult
from art_sim.domain.models import RelationshipType
from art_sim.security.sanitizer import SafeAssetReference


class RemediationKind(StrEnum):
    """Supported non-destructive infrastructure-as-code patch families."""

    KUBERNETES_NETWORK_POLICY = "kubernetes_network_policy"
    AWS_IAM_POLICY = "aws_iam_policy"


class RemediationAction(StrEnum):
    """Abstract defensive changes that can be simulated but never automatically applied."""

    DISABLE_RELATIONSHIP = "disable_relationship"
    RESTRICT_TRUST = "restrict_trust"
    REMOVE_EXCESSIVE_PERMISSION = "remove_excessive_permission"


class ExportFormat(StrEnum):
    """Supported review artifacts generated from normalized remediation data."""

    JSON = "json"
    TERRAFORM = "terraform"
    OPENTOFU = "opentofu"
    OPA_REGO = "opa_rego"
    GATEKEEPER = "gatekeeper"


class ApprovalDecision(StrEnum):
    """The only decisions a human operator may make for a proposed remediation."""

    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalStatus(StrEnum):
    """Lifecycle state of the human approval gate."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class VerificationStatus(StrEnum):
    """Outcome of a post-remediation analysis against the simulated graph."""

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    FAILED = "failed"
    NOT_RUN = "not_run"


class NormalizedRemediation(BaseModel):
    """Intermediate, reviewable remediation representation independent of output format."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    remediation_id: UUID = Field(default_factory=uuid4)
    action: RemediationAction
    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: RelationshipType
    resource: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=512)
    expected_risk_reduction: float = Field(ge=0.0, le=100.0)
    simulated_only: bool = True


class ExportedRemediation(BaseModel):
    """Validated text artifact generated from a normalized remediation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    export_format: ExportFormat
    file_name: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,128}$")
    content: str = Field(min_length=2, max_length=50_000)


class ApprovalRecord(BaseModel):
    """Non-secret audit record identifying who decided on a remediation proposal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: UUID = Field(default_factory=uuid4)
    remediation_id: UUID
    operator: str = Field(min_length=1, max_length=128)
    decision: ApprovalDecision
    risk_score: float = Field(ge=0.0, le=100.0)
    reason: str = Field(min_length=1, max_length=512)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class VerificationResult(BaseModel):
    """Before/after comparison derived from post-remediation simulated graph analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: VerificationStatus
    paths_removed: int = Field(ge=0)
    remaining_paths: int = Field(ge=0)
    risk_before: float = Field(ge=0.0, le=100.0)
    risk_after: float = Field(ge=0.0, le=100.0)
    risk_reduction: float = Field(ge=0.0, le=100.0)
    blast_radius_before: BlastRadiusResult
    blast_radius_after: BlastRadiusResult


class RemediationPrompt(BaseModel):
    """Structured, allow-listed context passed to a remediation generator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: UUID
    target_asset_id: UUID
    target_asset_type: str = Field(pattern=r"^[a-z_]+$")
    simulated_actions: tuple[SimulationAction, ...] = Field(min_length=1, max_length=8)
    remediation_kind: RemediationKind
    constraints: tuple[str, ...] = Field(min_length=3, max_length=8)


class RemediationArtifact(BaseModel):
    """An idempotent policy candidate suitable for review in a pull request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    remediation_kind: RemediationKind
    file_path: str = Field(
        pattern=r"^(kubernetes/network-policies|aws/iam-policies)/[a-z0-9-]+\.(yaml|json)$"
    )
    content: str = Field(min_length=32, max_length=20_000)
    summary: str = Field(min_length=1, max_length=256)
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def verify_content_digest(self) -> RemediationArtifact:
        """Prevent publication of content that differs from the reviewed artifact."""
        if sha256(self.content.encode("utf-8")).hexdigest() != self.content_sha256:
            raise ValueError("content_sha256 does not match content")
        return self


class RemediationRequest(BaseModel):
    """Approved inputs; raw logs, scanner output, and Kubernetes metadata are absent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: AttackPlan
    simulation: SimulationResult
    target: SafeAssetReference

    @model_validator(mode="after")
    def target_must_match_plan(self) -> RemediationRequest:
        """Bind the patch candidate to the target simulated by the attack plan."""
        if self.target.asset_id != self.plan.target_asset_id:
            raise ValueError("target asset must match the attack plan target")
        return self


class PullRequestReceipt(BaseModel):
    """Stable result returned after a remediation candidate is published or reused."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    number: int = Field(ge=1)
    url: str = Field(pattern=r"^https://")
    branch: str = Field(pattern=r"^ctem/remediation/[a-f0-9]{16}$")
    created_commit: bool
