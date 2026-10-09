"""Prompt-injection defenses for data that could eventually reach an LLM."""

from __future__ import annotations

import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from art_sim.domain.models import Asset, AssetType, AttackPath, RelationshipType


class SafeAssetReference(BaseModel):
    """Allow-listed asset representation that deliberately excludes names and tags."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_id: UUID
    asset_type: AssetType
    environment: str = Field(pattern=r"^[a-z_]+$")
    is_crown_jewel: bool


class SafeTopologyHop(BaseModel):
    """Allow-listed traversal representation that excludes relationship properties."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: RelationshipType


class SanitizedTopologyContext(BaseModel):
    """Data contract safe to hand to a future LLM-backed planner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_asset_id: UUID
    target_asset_id: UUID
    assets: tuple[SafeAssetReference, ...] = Field(min_length=2, max_length=9)
    hops: tuple[SafeTopologyHop, ...] = Field(min_length=1, max_length=8)


class PromptInjectionSanitizer:
    """Remove control text and never expose raw scanner/Kubernetes fields to planners."""

    _CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
    _INSTRUCTION_MARKERS = re.compile(
        r"(?i)\b(ignore\s+(all|any|previous)|system\s+prompt|developer\s+message|"
        r"tool\s+call|assistant\s+instruction)\b"
    )

    def sanitize_text(self, value: str, *, max_length: int = 512) -> str:
        """Bound untrusted text and redact common instruction-shaped prompt injections."""
        normalized = self._CONTROL_CHARACTERS.sub(" ", value).strip()
        normalized = self._INSTRUCTION_MARKERS.sub("[redacted]", normalized)
        # Strip again after truncation so a cut that lands on whitespace cannot leave a
        # trailing/leading space; this also makes the transform idempotent.
        return normalized[:max_length].strip()

    def build_topology_context(
        self, path: AttackPath, assets: tuple[Asset, ...]
    ) -> SanitizedTopologyContext:
        """Project graph objects into an allow-list; raw text is intentionally discarded."""
        assets_by_id = {asset.asset_id: asset for asset in assets}
        if set(path.asset_ids) != set(assets_by_id):
            raise ValueError("assets must exactly cover the attack path")
        return SanitizedTopologyContext(
            source_asset_id=path.source_asset_id,
            target_asset_id=path.target_asset_id,
            assets=tuple(
                SafeAssetReference(
                    asset_id=asset_id,
                    asset_type=assets_by_id[asset_id].asset_type,
                    environment=assets_by_id[asset_id].environment.value,
                    is_crown_jewel=assets_by_id[asset_id].is_crown_jewel,
                )
                for asset_id in path.asset_ids
            ),
            hops=tuple(
                SafeTopologyHop(
                    source_asset_id=step.source_asset_id,
                    target_asset_id=step.target_asset_id,
                    relationship_type=step.relationship_type,
                )
                for step in path.steps
            ),
        )
