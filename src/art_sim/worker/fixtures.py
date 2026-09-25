"""Controlled development scenarios containing no external infrastructure handles."""

from __future__ import annotations

from uuid import NAMESPACE_URL, UUID, uuid5

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


def shadow_scenario_catalog() -> tuple[SimulationScenario, ...]:
    """Return diverse, deterministic Shadow routes for local batch demonstrations."""
    return (
        shadow_demo_scenario(),
        _linear_scenario(
            "shadow-network-lateral",
            (AssetType.KUBERNETES_WORKLOAD, AssetType.KUBERNETES_SERVICE, AssetType.DATABASE),
            (RelationshipType.NETWORK_REACHABLE, RelationshipType.HOSTS),
        ),
        _linear_scenario(
            "shadow-trust-escalation",
            (AssetType.SYNTHETIC_CREDENTIAL, AssetType.IAM_ROLE, AssetType.SECRET),
            (RelationshipType.TRUSTS, RelationshipType.ASSUMES_ROLE),
        ),
        _linear_scenario(
            "shadow-public-service",
            (AssetType.INTERNET, AssetType.KUBERNETES_SERVICE, AssetType.STORAGE),
            (RelationshipType.EXPOSES, RelationshipType.HOSTS),
        ),
        _linear_scenario(
            "shadow-hybrid-chain",
            (AssetType.COMPUTE, AssetType.NETWORK, AssetType.IAM_ROLE, AssetType.DATABASE),
            (
                RelationshipType.NETWORK_REACHABLE,
                RelationshipType.TRUSTS,
                RelationshipType.ASSUMES_ROLE,
            ),
        ),
    )


def _linear_scenario(
    scenario_id: str,
    asset_types: tuple[AssetType, ...],
    relationship_types: tuple[RelationshipType, ...],
) -> SimulationScenario:
    """Build one isolated linear route without external infrastructure identifiers."""
    if len(asset_types) != len(relationship_types) + 1:
        raise ValueError("A linear scenario requires one more asset than relationship")
    asset_ids = tuple(
        uuid5(NAMESPACE_URL, f"art-sim:{scenario_id}:asset:{index}")
        for index in range(len(asset_types))
    )
    assets = tuple(
        Asset(
            asset_id=asset_id,
            name=f"{scenario_id}-asset-{index}",
            asset_type=asset_type,
            environment=Environment.SHADOW,
            criticality=(
                Criticality.CRITICAL
                if index == len(asset_types) - 1
                else Criticality.HIGH
                if index > 0
                else Criticality.MEDIUM
            ),
            is_crown_jewel=index == len(asset_types) - 1,
            provider="synthetic",
        )
        for index, (asset_id, asset_type) in enumerate(zip(asset_ids, asset_types, strict=True))
    )
    relationships = tuple(
        AssetRelationship(
            source_asset_id=asset_ids[index],
            target_asset_id=asset_ids[index + 1],
            relationship_type=relationship_type,
        )
        for index, relationship_type in enumerate(relationship_types)
    )
    return SimulationScenario(
        scenario_id=scenario_id,
        graph_version=f"{scenario_id}-v1",
        source_asset_id=asset_ids[0],
        graph=SimulatedAttackGraph(assets=assets, relationships=relationships),
        requires_approval=True,
    )
