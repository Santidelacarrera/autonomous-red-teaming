"""Seed a small, idempotent Shadow topology through the production repository API."""

from __future__ import annotations

import asyncio
import os
from uuid import NAMESPACE_URL, uuid5

from dotenv import load_dotenv
from pydantic import SecretStr

from art_sim.domain.models import (
    Asset,
    AssetRelationship,
    AssetType,
    Criticality,
    Environment,
    Identity,
    RelationshipType,
    Vulnerability,
)
from art_sim.infrastructure.config import Neo4jSettings
from art_sim.infrastructure.cypher_validator import CypherValidator
from art_sim.infrastructure.neo4j_graph_repository import Neo4jGraphRepository

SOURCE_ASSET_ID = uuid5(NAMESPACE_URL, "art-sim:shadow:web-frontend")
IAM_ROLE_ASSET_ID = uuid5(NAMESPACE_URL, "art-sim:shadow:db-access-role")
CROWN_JEWEL_ASSET_ID = uuid5(NAMESPACE_URL, "art-sim:shadow:customer-database")
SERVICE_IDENTITY_ID = uuid5(NAMESPACE_URL, "art-sim:shadow:web-service-account")
VULNERABILITY_ID = uuid5(NAMESPACE_URL, "art-sim:shadow:CVE-2023-38606")


def load_neo4j_settings() -> Neo4jSettings:
    """Load required Neo4j connection values without printing secrets."""
    load_dotenv(override=True)  # <-- Fuerza la relectura del archivo .env
    uri = os.getenv("NEO4J_URI")
    password = os.getenv("NEO4J_PASSWORD")
    if not uri or not password:
        raise RuntimeError("NEO4J_URI and NEO4J_PASSWORD must be configured in .env")
    return Neo4jSettings(
        uri=uri,
        username=os.getenv("NEO4J_USER") or os.getenv("NEO4J_USERNAME") or "neo4j",
        password=SecretStr(password),
    )


async def seed_database() -> None:
    """Create an EKS-to-IAM-to-database path without destructive cleanup."""
    repository = Neo4jGraphRepository(load_neo4j_settings(), CypherValidator())
    async with repository:
        source = Asset(
            asset_id=SOURCE_ASSET_ID,
            name="shadow-web-frontend",
            asset_type=AssetType.KUBERNETES_WORKLOAD,
            environment=Environment.SHADOW,
            provider="aws",
            region="us-east-1",
            tags={"ctem.openai.com/scenario": "shadow-e2e"},
        )
        role = Asset(
            asset_id=IAM_ROLE_ASSET_ID,
            name="shadow-db-access-role",
            asset_type=AssetType.IAM_ROLE,
            environment=Environment.SHADOW,
            criticality=Criticality.HIGH,
            provider="aws",
        )
        database = Asset(
            asset_id=CROWN_JEWEL_ASSET_ID,
            name="shadow-customer-database",
            asset_type=AssetType.DATABASE,
            environment=Environment.SHADOW,
            criticality=Criticality.CRITICAL,
            is_crown_jewel=True,
            provider="aws",
            region="us-east-1",
        )
        for asset in (source, role, database):
            await repository.upsert_asset(asset)

        await repository.upsert_identity(
            Identity(
                identity_id=SERVICE_IDENTITY_ID,
                principal="system:serviceaccount:shadow:web-sa",
                provider="kubernetes",
                environment=Environment.SHADOW,
                roles=("shadow-db-access",),
            )
        )
        await repository.upsert_vulnerability(
            Vulnerability(
                vulnerability_id=VULNERABILITY_ID,
                cve_id="CVE-2023-38606",
                title="Shadow workload remote-code-execution simulation",
                severity=Criticality.CRITICAL,
                cvss_score=9.8,
                affected_asset_id=SOURCE_ASSET_ID,
                is_exploitable=True,
            )
        )
        for relationship in (
            AssetRelationship(
                source_asset_id=SOURCE_ASSET_ID,
                target_asset_id=IAM_ROLE_ASSET_ID,
                relationship_type=RelationshipType.ASSUMES_ROLE,
            ),
            AssetRelationship(
                source_asset_id=IAM_ROLE_ASSET_ID,
                target_asset_id=CROWN_JEWEL_ASSET_ID,
                relationship_type=RelationshipType.TRUSTS,
            ),
        ):
            await repository.upsert_asset_relationship(relationship)

    print("Shadow topology seeded successfully.")
    print(f"Run E2E from source asset: {SOURCE_ASSET_ID}")


if __name__ == "__main__":
    asyncio.run(seed_database())
