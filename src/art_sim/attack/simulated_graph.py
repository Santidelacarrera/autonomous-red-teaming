"""Pure in-memory graph used for safe remediation verification and test scenarios."""

from __future__ import annotations

from collections import deque
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from art_sim.domain.exceptions import TopologyNotFoundError
from art_sim.domain.models import Asset, AssetRelationship, AttackPath, AttackPathStep


class SimulatedAttackGraph(BaseModel):
    """Immutable graph fixture; it cannot execute or modify external infrastructure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assets: tuple[Asset, ...] = Field(min_length=1, max_length=1_000)
    relationships: tuple[AssetRelationship, ...] = Field(max_length=5_000)

    def fork(self) -> SimulatedAttackGraph:
        """Deep-copy the complete simulated graph before a verification or what-if run.

        Domain models are frozen but their mapping fields can otherwise retain mutable
        references. Every simulation must start from this isolation boundary.
        """
        return self.model_copy(deep=True)

    def find_shortest_path_to_crown_jewel(self, source_asset_id: UUID, *, max_hops: int = 8) -> AttackPath:
        """Perform deterministic bounded BFS over simulated relationships only."""
        if not 1 <= max_hops <= 32:
            raise ValueError("max_hops must be between 1 and 32")
        assets_by_id = {asset.asset_id: asset for asset in self.assets}
        if source_asset_id not in assets_by_id:
            raise TopologyNotFoundError("Simulated source asset does not exist")
        adjacency: dict[UUID, list[AssetRelationship]] = {}
        for relationship in self.relationships:
            adjacency.setdefault(relationship.source_asset_id, []).append(relationship)
        for relationships in adjacency.values():
            relationships.sort(key=lambda item: (str(item.target_asset_id), item.relationship_type.value))
        queue: deque[tuple[UUID, tuple[UUID, ...], tuple[AssetRelationship, ...]]] = deque(
            [(source_asset_id, (source_asset_id,), ())]
        )
        visited = {source_asset_id}
        while queue:
            current_id, node_ids, edges = queue.popleft()
            if current_id != source_asset_id and self._is_crown_jewel(assets_by_id[current_id]):
                return AttackPath(
                    source_asset_id=source_asset_id,
                    target_asset_id=current_id,
                    asset_ids=node_ids,
                    steps=tuple(
                        AttackPathStep(
                            source_asset_id=edge.source_asset_id,
                            target_asset_id=edge.target_asset_id,
                            relationship_type=edge.relationship_type,
                            properties=edge.properties,
                        )
                        for edge in edges
                    ),
                    hop_count=len(edges),
                )
            if len(edges) == max_hops:
                continue
            for edge in adjacency.get(current_id, []):
                if edge.target_asset_id not in assets_by_id or edge.target_asset_id in visited:
                    continue
                visited.add(edge.target_asset_id)
                queue.append((edge.target_asset_id, (*node_ids, edge.target_asset_id), (*edges, edge)))
        raise TopologyNotFoundError("No simulated path to a crown jewel exists")

    def without_relationship(self, relationship: AssetRelationship) -> SimulatedAttackGraph:
        """Return a graph copy with exactly one modeled edge removed for verification."""
        shadow = self.fork()
        remaining = tuple(
            item
            for item in shadow.relationships
            if not self._same_edge(item, relationship)
        )
        return shadow.model_copy(update={"relationships": remaining})

    def with_relationship_properties(
        self, relationship: AssetRelationship, properties: dict[str, str]
    ) -> SimulatedAttackGraph:
        """Return an isolated graph with one edge property map replaced, never mutated."""
        shadow = self.fork()
        updated_relationships = tuple(
            item.model_copy(update={"properties": dict(properties)})
            if self._same_edge(item, relationship)
            else item.model_copy(deep=True)
            for item in shadow.relationships
        )
        return shadow.model_copy(update={"relationships": updated_relationships})

    @staticmethod
    def _same_edge(left: AssetRelationship, right: AssetRelationship) -> bool:
        """Compare stable edge identity independently from mutable relation properties."""
        return (
            left.source_asset_id == right.source_asset_id
            and left.target_asset_id == right.target_asset_id
            and left.relationship_type is right.relationship_type
        )

    @staticmethod
    def _is_crown_jewel(asset: Asset) -> bool:
        """Use the existing asset classification; no parallel crown-jewel system exists."""
        return asset.is_crown_jewel
