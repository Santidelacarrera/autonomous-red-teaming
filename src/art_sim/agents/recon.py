"""Graph-based reconnaissance that bounds the planner input before orchestration."""

from __future__ import annotations

from uuid import UUID

from art_sim.domain.exceptions import ScopeViolationError, TopologyNotFoundError
from art_sim.domain.models import Asset, AttackPath, Environment
from art_sim.domain.repositories import GraphRepository
from art_sim.security.sanitizer import PromptInjectionSanitizer, SanitizedTopologyContext


class ReconAgent:
    """Extract one minimal, shadow-only candidate path using the graph repository."""

    def __init__(self, repository: GraphRepository, sanitizer: PromptInjectionSanitizer) -> None:
        """Inject persistence and sanitization boundaries explicitly."""
        self._repository = repository
        self._sanitizer = sanitizer

    async def discover(
        self, source_asset_id: UUID, allowed_asset_ids: frozenset[UUID]
    ) -> tuple[AttackPath, SanitizedTopologyContext, tuple[Asset, ...]]:
        """Return a shortest path projection only when every asset is in Shadow scope."""
        path = await self._repository.find_shortest_path_to_crown_jewel(source_asset_id)
        assets = await self._repository.get_assets(path.asset_ids)
        self._validate_shadow_path(path.asset_ids, assets, allowed_asset_ids)
        return path, self._sanitizer.build_topology_context(path, assets), assets

    @staticmethod
    def _validate_shadow_path(
        path_asset_ids: tuple[UUID, ...], assets: tuple[Asset, ...], allowed_asset_ids: frozenset[UUID]
    ) -> None:
        """Fail closed if the repository cannot prove a complete Shadow-only path."""
        if len(assets) != len(path_asset_ids):
            raise TopologyNotFoundError("Topology lookup did not return every asset in the candidate path")
        if not set(path_asset_ids).issubset(allowed_asset_ids):
            raise ScopeViolationError.from_code("asset_scope", "Recon path crosses the approved scope.")
        if any(asset.environment is not Environment.SHADOW for asset in assets):
            raise ScopeViolationError.from_code("environment_scope", "Recon path contains a non-shadow asset.")
