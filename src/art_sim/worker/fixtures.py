"""Controlled development scenarios containing no external infrastructure handles."""

from __future__ import annotations

from uuid import UUID

from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.domain.models import (
    Asset,
    AssetRelationship,
    AssetType,
    Criticality,
    Environment,
    RelationshipType,
)
from art_sim.worker.models import SimulationScenario


def shadow_demo_scenario(*, requires_approval: bool = True) -> SimulationScenario:
    """Build a deterministic, synthetic path used by local development and tests."""
    source_id = UUID("10000000-0000-4000-8000-000000000001")
    role_id = UUID("10000000-0000-4000-8000-000000000002")
    database_id = UUID("10000000-0000-4000-8000-000000000003")
    graph = SimulatedAttackGraph(
        assets=(
            Asset(
                asset_id=source_id,
                name="shadow-workload",
                asset_type=AssetType.KUBERNETES_WORKLOAD,
                environment=Environment.SHADOW,
                provider="synthetic",
            ),
            Asset(
                asset_id=role_id,
                name="shadow-role",
                asset_type=AssetType.IAM_ROLE,
                environment=Environment.SHADOW,
                criticality=Criticality.HIGH,
                provider="synthetic",
            ),
            Asset(
                asset_id=database_id,
                name="shadow-database",
                asset_type=AssetType.DATABASE,
                environment=Environment.SHADOW,
                criticality=Criticality.CRITICAL,
                is_crown_jewel=True,
                provider="synthetic",
            ),
        ),
        relationships=(
            AssetRelationship(
                source_asset_id=source_id,
                target_asset_id=role_id,
                relationship_type=RelationshipType.EXPOSES,
            ),
            AssetRelationship(
                source_asset_id=role_id,
                target_asset_id=database_id,
                relationship_type=RelationshipType.ASSUMES_ROLE,
            ),
        ),
    )
    return SimulationScenario(
        scenario_id="shadow-demo",
        graph_version="shadow-fixture-v1",
        source_asset_id=source_id,
        graph=graph,
        requires_approval=requires_approval,
    )
