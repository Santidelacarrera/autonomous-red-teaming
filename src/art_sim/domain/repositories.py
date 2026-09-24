"""Repository ports that keep domain services independent from Neo4j."""

from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from art_sim.domain.models import Asset, AssetRelationship, AttackPath, Identity, Vulnerability


class GraphRepository(ABC):
    """Asynchronous persistence port for the infrastructure attack graph."""

    @abstractmethod
    async def upsert_asset(self, asset: Asset) -> None:
        """Persist one asset idempotently."""

    @abstractmethod
    async def upsert_identity(self, identity: Identity) -> None:
        """Persist one identity idempotently."""

    @abstractmethod
    async def upsert_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Persist a vulnerability and its affected-asset link idempotently."""

    @abstractmethod
    async def upsert_asset_relationship(self, relationship: AssetRelationship) -> None:
        """Persist one allow-listed topology edge idempotently."""

    @abstractmethod
    async def get_assets(self, asset_ids: tuple[UUID, ...]) -> tuple[Asset, ...]:
        """Return the requested assets in caller supplied order for scope verification."""

    @abstractmethod
    async def find_shortest_path_to_crown_jewel(
        self, source_asset_id: UUID, *, max_hops: int = 8
    ) -> AttackPath:
        """Return the lexicographically deterministic shortest candidate path."""
