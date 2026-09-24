"""Read-only repositories over isolated in-memory Shadow graph fixtures."""

from __future__ import annotations

from uuid import UUID

from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.domain.exceptions import ScopeViolationError, TopologyNotFoundError
from art_sim.domain.models import Asset, AssetRelationship, AttackPath, Identity, Vulnerability
from art_sim.domain.repositories import GraphRepository
from art_sim.worker.models import SimulationScenario
from art_sim.worker.ports import ScenarioRepository


class ShadowGraphRepository(GraphRepository):
    """Expose graph reads while making every mutation operation fail closed."""

    def __init__(self, graph: SimulatedAttackGraph) -> None:
        self._graph = graph.fork()

    async def upsert_asset(self, asset: Asset) -> None:
        del asset
        self._deny_write()

    async def upsert_identity(self, identity: Identity) -> None:
        del identity
        self._deny_write()

    async def upsert_vulnerability(self, vulnerability: Vulnerability) -> None:
        del vulnerability
        self._deny_write()

    async def upsert_asset_relationship(self, relationship: AssetRelationship) -> None:
        del relationship
        self._deny_write()

    async def get_assets(self, asset_ids: tuple[UUID, ...]) -> tuple[Asset, ...]:
        """Return deep-copied assets in caller order or reject incomplete topology."""
        assets = {asset.asset_id: asset for asset in self._graph.assets}
        if any(asset_id not in assets for asset_id in asset_ids):
            raise TopologyNotFoundError("Shadow topology does not contain every requested asset")
        return tuple(assets[asset_id].model_copy(deep=True) for asset_id in asset_ids)

    async def find_shortest_path_to_crown_jewel(
        self, source_asset_id: UUID, *, max_hops: int = 8
    ) -> AttackPath:
        """Run only the deterministic in-memory Shadow traversal."""
        return self._graph.find_shortest_path_to_crown_jewel(source_asset_id, max_hops=max_hops)

    @staticmethod
    def _deny_write() -> None:
        raise ScopeViolationError.from_code(
            "shadow_read_only",
            "The worker graph repository does not permit mutation operations.",
        )


class InMemoryScenarioRepository(ScenarioRepository):
    """Immutable local scenario adapter; production may inject a durable catalog."""

    def __init__(self, scenarios: tuple[SimulationScenario, ...]) -> None:
        if not scenarios or len({scenario.scenario_id for scenario in scenarios}) != len(scenarios):
            raise ValueError("Scenario repository requires unique configured scenarios")
        self._scenarios = {scenario.scenario_id: scenario for scenario in scenarios}

    async def get(self, scenario_id: str) -> SimulationScenario:
        """Return one configured scenario without accepting arbitrary client payloads."""
        try:
            return self._scenarios[scenario_id].model_copy(deep=True)
        except KeyError as error:
            raise TopologyNotFoundError("Configured Shadow scenario does not exist") from error
