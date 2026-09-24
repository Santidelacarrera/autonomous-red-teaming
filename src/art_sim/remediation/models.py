"""Safe, typed remediation contracts for generated policy candidates."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from art_sim.agents.models import AttackPlan, SimulationAction, SimulationResult
from art_sim.security.sanitizer import SafeAssetReference


class RemediationKind(StrEnum):
    """Supported non-destructive infrastructure-as-code patch families."""

    KUBERNETES_NETWORK_POLICY = "kubernetes_network_policy"
    AWS_IAM_POLICY = "aws_iam_policy"


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
