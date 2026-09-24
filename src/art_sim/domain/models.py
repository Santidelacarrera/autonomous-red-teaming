"""Pydantic v2 entities used by the graph-engine bounded context."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

NonEmptyText = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9._:/@+=-]+$")]


class AssetType(StrEnum):
    """Infrastructure types that can participate in an attack graph."""

    COMPUTE = "compute"
    DATABASE = "database"
    SECRET = "secret"
    KUBERNETES_WORKLOAD = "kubernetes_workload"
    KUBERNETES_NODE = "kubernetes_node"
    KUBERNETES_SERVICE = "kubernetes_service"
    IAM_ROLE = "iam_role"
    NETWORK = "network"
    STORAGE = "storage"
    SYNTHETIC_CREDENTIAL = "synthetic_credential"
    INTERNET = "internet"


class Environment(StrEnum):
    """Deployment environment and therefore simulation boundary."""

    SHADOW = "shadow"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Criticality(StrEnum):
    """Business impact classification for an asset."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RelationshipType(StrEnum):
    """Explicit, allow-listed topology edges persisted in Neo4j."""

    NETWORK_REACHABLE = "NETWORK_REACHABLE"
    TRUSTS = "TRUSTS"
    ASSUMES_ROLE = "ASSUMES_ROLE"
    EXPOSES = "EXPOSES"
    HOSTS = "HOSTS"
    CONTAINER_ESCAPE = "CONTAINER_ESCAPE"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    IAM_ASSUME_ROLE = "IAM_ASSUME_ROLE"
    ACCESS = "ACCESS"


class Asset(BaseModel):
    """A normalized cloud or Kubernetes resource represented in the graph."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    asset_id: UUID = Field(default_factory=uuid4)
    name: NonEmptyText
    asset_type: AssetType
    environment: Environment
    criticality: Criticality = Criticality.MEDIUM
    is_crown_jewel: bool = False
    provider: NonEmptyText
    region: str | None = Field(default=None, max_length=64)
    tags: dict[str, str] = Field(default_factory=dict, max_length=50)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, tags: dict[str, str]) -> dict[str, str]:
        """Reject oversized or non-string tag material before persistence."""
        if any(not key.strip() or len(key) > 128 or len(value) > 512 for key, value in tags.items()):
            raise ValueError("tags must contain non-empty keys and bounded string values")
        return tags


class Identity(BaseModel):
    """A human or machine principal that can grant graph traversal capability."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    identity_id: UUID = Field(default_factory=uuid4)
    principal: NonEmptyText
    provider: NonEmptyText
    environment: Environment
    is_privileged: bool = False
    roles: tuple[NonEmptyText, ...] = Field(default_factory=tuple, max_length=100)


class Vulnerability(BaseModel):
    """Validated vulnerability evidence linked to an asset, never raw scanner output."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    vulnerability_id: UUID = Field(default_factory=uuid4)
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str = Field(min_length=1, max_length=256)
    severity: Criticality
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: str | None = Field(
        default=None,
        pattern=r"^CVSS:3\.[01]/[A-Z]{1,3}:[A-Z](?:/[A-Z]{1,3}:[A-Z])+$",
        max_length=128,
    )
    affected_asset_id: UUID
    evidence_url: HttpUrl | None = None
    is_exploitable: bool = False
    exploit_available: bool | None = None
    affected_component: str | None = Field(default=None, max_length=128)
    fixed_version: str | None = Field(default=None, max_length=64)

    @property
    def is_exploit_available(self) -> bool:
        """Expose the newer field while preserving the prior `is_exploitable` contract."""
        return self.exploit_available if self.exploit_available is not None else self.is_exploitable


class AssetRelationship(BaseModel):
    """A directed, typed link between two assets in the topology."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: RelationshipType
    properties: dict[str, str] = Field(default_factory=dict, max_length=20)

    @model_validator(mode="after")
    def source_and_target_must_differ(self) -> AssetRelationship:
        """Prevent self-loops that create non-actionable traversal noise."""
        if self.source_asset_id == self.target_asset_id:
            raise ValueError("source_asset_id and target_asset_id must differ")
        return self


class AttackPathStep(BaseModel):
    """One deterministic topology edge in a candidate attack path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: RelationshipType
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """A bounded, deterministic route to a crown jewel for later agent analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_asset_id: UUID
    target_asset_id: UUID
    asset_ids: tuple[UUID, ...] = Field(min_length=2)
    steps: tuple[AttackPathStep, ...] = Field(min_length=1)
    hop_count: int = Field(ge=1, le=32)

    @model_validator(mode="after")
    def validate_path_shape(self) -> AttackPath:
        """Guarantee a contiguous path before it enters an agent state in Phase 2."""
        if self.asset_ids[0] != self.source_asset_id or self.asset_ids[-1] != self.target_asset_id:
            raise ValueError("asset_ids must begin at source and end at target")
        if len(self.steps) != self.hop_count or len(self.asset_ids) != self.hop_count + 1:
            raise ValueError("hop_count, asset_ids, and steps are inconsistent")
        for index, step in enumerate(self.steps):
            if step.source_asset_id != self.asset_ids[index] or step.target_asset_id != self.asset_ids[index + 1]:
                raise ValueError("steps must form a contiguous sequence matching asset_ids")
        return self
