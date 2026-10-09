"""The demonstration laboratory: a fictional estate that exists only in memory.

Nothing here names, scans or contacts a real system. Every asset is a ``Environment.SHADOW``
node with provider ``synthetic``; identifiers are ``uuid5`` of the asset name so the same
lab always yields the same graph, risk score and remediation — which is what lets an outside
reviewer reproduce and check the published digest.

Topology (arrows are modeled traversal relations, not network flows)::

    internet ─EXPOSES→ web-frontend ─NETWORK_REACHABLE→ api-workload ─CONTAINER_ESCAPE→ k8s-node
                            │                               │                              │
                            └→ worker-workload              └─ACCESS→ analytics-db         CREDENTIAL_ACCESS
                                     │ ACCESS                                              ↓
                                     ↓                                              node-credentials
                                 log-bucket                                                │ ASSUMES_ROLE
                                                                                           ↓
              audit-archive (isolated)            billing-db ←─ACCESS─ deploy-role ←───────┘
"""

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

LAB_SCENARIO_ID = "lab-ecommerce"
LAB_GRAPH_VERSION = "lab-ecommerce-v1"
SOURCE_NAME = "internet"


def asset_id(name: str) -> UUID:
    """Stable identifier for a lab asset."""
    return uuid5(NAMESPACE_URL, f"art-sim:lab:{LAB_SCENARIO_ID}:{name}")


_ASSETS: tuple[tuple[str, AssetType, Criticality, bool], ...] = (
    ("internet", AssetType.INTERNET, Criticality.LOW, False),
    ("web-frontend", AssetType.KUBERNETES_SERVICE, Criticality.MEDIUM, False),
    ("api-workload", AssetType.KUBERNETES_WORKLOAD, Criticality.MEDIUM, False),
    ("worker-workload", AssetType.KUBERNETES_WORKLOAD, Criticality.LOW, False),
    ("log-bucket", AssetType.STORAGE, Criticality.LOW, False),
    ("analytics-db", AssetType.DATABASE, Criticality.HIGH, False),
    ("k8s-node", AssetType.KUBERNETES_NODE, Criticality.HIGH, False),
    ("node-credentials", AssetType.SYNTHETIC_CREDENTIAL, Criticality.HIGH, False),
    ("deploy-role", AssetType.IAM_ROLE, Criticality.HIGH, False),
    ("billing-db", AssetType.DATABASE, Criticality.CRITICAL, True),
    ("audit-archive", AssetType.STORAGE, Criticality.MEDIUM, False),
)

_EDGES: tuple[tuple[str, str, RelationshipType], ...] = (
    ("internet", "web-frontend", RelationshipType.EXPOSES),
    ("web-frontend", "api-workload", RelationshipType.NETWORK_REACHABLE),
    ("web-frontend", "worker-workload", RelationshipType.NETWORK_REACHABLE),
    ("worker-workload", "log-bucket", RelationshipType.ACCESS),
    ("api-workload", "analytics-db", RelationshipType.ACCESS),
    ("api-workload", "k8s-node", RelationshipType.CONTAINER_ESCAPE),
    ("k8s-node", "node-credentials", RelationshipType.CREDENTIAL_ACCESS),
    ("node-credentials", "deploy-role", RelationshipType.ASSUMES_ROLE),
    ("deploy-role", "billing-db", RelationshipType.ACCESS),
)


def lab_graph() -> SimulatedAttackGraph:
    """Build the immutable laboratory graph."""
    assets = tuple(
        Asset(
            asset_id=asset_id(name),
            name=name,
            asset_type=kind,
            environment=Environment.SHADOW,
            criticality=criticality,
            is_crown_jewel=crown,
            provider="synthetic",
        )
        for name, kind, criticality, crown in _ASSETS
    )
    relationships = tuple(
        AssetRelationship(
            source_asset_id=asset_id(source), target_asset_id=asset_id(target), relationship_type=kind
        )
        for source, target, kind in _EDGES
    )
    return SimulatedAttackGraph(assets=assets, relationships=relationships)


def lab_scenario() -> SimulationScenario:
    """The allow-listed scenario the demo submits; human approval is mandatory."""
    return SimulationScenario(
        scenario_id=LAB_SCENARIO_ID,
        graph_version=LAB_GRAPH_VERSION,
        source_asset_id=asset_id(SOURCE_NAME),
        graph=lab_graph(),
        requires_approval=True,
    )
