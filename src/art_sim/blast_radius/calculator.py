"""Blast-radius metrics derived from a simulated graph without external traversal."""

from __future__ import annotations

from collections import deque
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.domain.exceptions import TopologyNotFoundError
from art_sim.domain.models import Criticality


class BlastRadiusResult(BaseModel):
    """Reachability impact metrics with explicitly defined denominators."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_asset_id: UUID
    reachable_assets: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    reachable_critical_assets: int = Field(ge=0)
    total_critical_assets: int = Field(ge=0)
    reachable_crown_jewels: int = Field(ge=0)
    total_crown_jewels: int = Field(ge=0)
    blast_radius_percentage: float = Field(ge=0.0, le=100.0)
    critical_blast_radius_percentage: float = Field(ge=0.0, le=100.0)
    crown_jewel_exposure_percentage: float = Field(ge=0.0, le=100.0)


class BlastRadiusCalculator:
    """Calculate reachable assets from one simulated compromised source."""

    def calculate(self, graph: SimulatedAttackGraph, source_asset_id: UUID, *, max_hops: int = 10) -> BlastRadiusResult:
        """Traverse each simulated edge once and return percentage metrics rounded to 2 decimals."""
        if not 1 <= max_hops <= 32:
            raise ValueError("max_hops must be between 1 and 32")
        assets_by_id = {asset.asset_id: asset for asset in graph.assets}
        if source_asset_id not in assets_by_id:
            raise TopologyNotFoundError("Simulated source asset does not exist")
        adjacency: dict[UUID, tuple[UUID, ...]] = {}
        for relationship in graph.relationships:
            adjacency[relationship.source_asset_id] = (
                *adjacency.get(relationship.source_asset_id, ()), relationship.target_asset_id
            )
        reachable = self._reachable_ids(adjacency, source_asset_id, max_hops).difference({source_asset_id})
        relevant_assets = tuple(asset for asset in graph.assets if asset.asset_id != source_asset_id)
        critical_assets = tuple(asset for asset in relevant_assets if asset.criticality is Criticality.CRITICAL)
        crown_jewels = tuple(asset for asset in relevant_assets if asset.is_crown_jewel)
        reachable_critical = sum(asset.asset_id in reachable for asset in critical_assets)
        reachable_crown_jewels = sum(asset.asset_id in reachable for asset in crown_jewels)
        return BlastRadiusResult(
            source_asset_id=source_asset_id,
            reachable_assets=len(reachable),
            total_assets=len(relevant_assets),
            reachable_critical_assets=reachable_critical,
            total_critical_assets=len(critical_assets),
            reachable_crown_jewels=reachable_crown_jewels,
            total_crown_jewels=len(crown_jewels),
            blast_radius_percentage=self._percentage(len(reachable), len(relevant_assets)),
            critical_blast_radius_percentage=self._percentage(reachable_critical, len(critical_assets)),
            crown_jewel_exposure_percentage=self._percentage(reachable_crown_jewels, len(crown_jewels)),
        )

    @staticmethod
    def _reachable_ids(adjacency: dict[UUID, tuple[UUID, ...]], source: UUID, max_hops: int) -> set[UUID]:
        """Return reachability under a hard traversal budget."""
        queue: deque[tuple[UUID, int]] = deque(((source, 0),))
        visited = {source}
        while queue:
            node_id, hops = queue.popleft()
            if hops == max_hops:
                continue
            for target_id in adjacency.get(node_id, ()):
                if target_id not in visited:
                    visited.add(target_id)
                    queue.append((target_id, hops + 1))
        return visited

    @staticmethod
    def _percentage(numerator: int, denominator: int) -> float:
        """Avoid undefined ratios: no applicable assets yields zero exposure."""
        return round((100.0 * numerator / denominator) if denominator else 0.0, 2)
