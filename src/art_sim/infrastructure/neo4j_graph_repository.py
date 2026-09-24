"""Official asynchronous Neo4j adapter for graph topology and path queries."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Self, TypeVar
from uuid import UUID

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncManagedTransaction
from neo4j.exceptions import DriverError, Neo4jError, ServiceUnavailable, SessionExpired
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from art_sim.domain.exceptions import GraphConnectionError, GraphQueryError, TopologyNotFoundError
from art_sim.domain.models import (
    Asset,
    AssetRelationship,
    AssetType,
    AttackPath,
    AttackPathStep,
    Identity,
    RelationshipType,
    Vulnerability,
)
from art_sim.domain.repositories import GraphRepository
from art_sim.infrastructure.config import Neo4jSettings
from art_sim.infrastructure.cypher_validator import CypherIntent, CypherValidator

ResultT = TypeVar("ResultT")
RetryableGraphError = (ServiceUnavailable, SessionExpired)


class Neo4jGraphRepository(GraphRepository):
    """Neo4j implementation with DI, retries, validation, and idempotent writes."""

    _ASSET_QUERY = """
    MERGE (asset:Asset {asset_id: $asset_id})
    SET asset.name = $name,
        asset.asset_type = $asset_type,
        asset.environment = $environment,
        asset.criticality = $criticality,
        asset.is_crown_jewel = $is_crown_jewel,
        asset.provider = $provider,
        asset.region = $region,
        asset.tags = $tags
    """
    _IDENTITY_QUERY = """
    MERGE (identity:Identity {identity_id: $identity_id})
    SET identity.principal = $principal,
        identity.provider = $provider,
        identity.environment = $environment,
        identity.is_privileged = $is_privileged,
        identity.roles = $roles
    """
    _VULNERABILITY_QUERY = """
    MATCH (asset:Asset {asset_id: $affected_asset_id})
    MERGE (vulnerability:Vulnerability {vulnerability_id: $vulnerability_id})
    SET vulnerability.cve_id = $cve_id,
        vulnerability.title = $title,
        vulnerability.severity = $severity,
        vulnerability.cvss_score = $cvss_score,
        vulnerability.evidence_url = $evidence_url,
        vulnerability.is_exploitable = $is_exploitable
    MERGE (asset)-[:HAS_VULNERABILITY]->(vulnerability)
    """
    _RELATIONSHIP_QUERY = """
    MATCH (source:Asset {asset_id: $source_asset_id})
    MATCH (target:Asset {asset_id: $target_asset_id})
    MERGE (source)-[relationship:TOPOLOGY_EDGE {edge_key: $edge_key}]->(target)
    SET relationship.relationship_type = $relationship_type,
        relationship.properties = $properties
    """
    _GET_ASSETS_QUERY = """
    UNWIND $asset_ids AS requested_asset_id
    MATCH (asset:Asset {asset_id: requested_asset_id})
    RETURN asset
    """
    _SHORTEST_PATH_QUERY = """
    MATCH (source:Asset {asset_id: $source_asset_id})
    MATCH (target:Asset)
    WHERE target.is_crown_jewel = true OR target.asset_type IN $crown_jewel_types
    MATCH path = allShortestPaths(
        (source)-[:TOPOLOGY_EDGE*1..8]->(target)
    )
    WHERE length(path) <= $max_hops
    RETURN nodes(path) AS path_nodes, relationships(path) AS path_relationships, length(path) AS hop_count
    ORDER BY hop_count ASC, [node IN nodes(path) | node.asset_id] ASC
    LIMIT 1
    """

    def __init__(
        self,
        settings: Neo4jSettings,
        validator: CypherValidator,
        driver: AsyncDriver | None = None,
    ) -> None:
        """Construct the adapter; driver injection makes tests and lifecycle explicit."""
        self._settings = settings
        self._validator = validator
        self._driver = driver

    async def __aenter__(self) -> Self:
        """Open and verify the driver when used as an async context manager."""
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        """Release the connection pool on context exit."""
        await self.close()

    async def connect(self) -> None:
        """Create and verify an async driver with exponential backoff."""
        if self._driver is None:
            self._driver = AsyncGraphDatabase.driver(
                self._settings.uri,
                auth=(self._settings.username, self._settings.password.get_secret_value()),
                encrypted=self._settings.encrypted,
                max_connection_pool_size=self._settings.max_connection_pool_size,
            )
        try:
            await self._retry(lambda: self._require_driver().verify_connectivity())
        except (DriverError, Neo4jError) as error:
            await self.close()
            raise GraphConnectionError("Unable to establish verified Neo4j connectivity") from error

    async def close(self) -> None:
        """Close the current driver and clear it for a safe later reconnect."""
        if self._driver is not None:
            await self._driver.close()
            self._driver = None

    async def upsert_asset(self, asset: Asset) -> None:
        """Persist an asset idempotently by immutable asset identifier."""
        await self._execute_write(self._ASSET_QUERY, self._asset_parameters(asset))

    async def upsert_identity(self, identity: Identity) -> None:
        """Persist an identity idempotently by immutable identity identifier."""
        parameters: dict[str, object] = {
            "identity_id": str(identity.identity_id),
            "principal": identity.principal,
            "provider": identity.provider,
            "environment": identity.environment.value,
            "is_privileged": identity.is_privileged,
            "roles": list(identity.roles),
        }
        await self._execute_write(self._IDENTITY_QUERY, parameters)

    async def upsert_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Persist scanner-normalized evidence and an asset link in one transaction."""
        parameters: dict[str, object] = {
            "vulnerability_id": str(vulnerability.vulnerability_id),
            "cve_id": vulnerability.cve_id,
            "title": vulnerability.title,
            "severity": vulnerability.severity.value,
            "cvss_score": vulnerability.cvss_score,
            "affected_asset_id": str(vulnerability.affected_asset_id),
            "evidence_url": str(vulnerability.evidence_url) if vulnerability.evidence_url else None,
            "is_exploitable": vulnerability.is_exploitable,
        }
        await self._execute_write(self._VULNERABILITY_QUERY, parameters)

    async def upsert_asset_relationship(self, relationship: AssetRelationship) -> None:
        """Persist an allow-listed topology relationship idempotently."""
        parameters: dict[str, object] = {
            "source_asset_id": str(relationship.source_asset_id),
            "target_asset_id": str(relationship.target_asset_id),
            "relationship_type": relationship.relationship_type.value,
            "properties": relationship.properties,
            "edge_key": f"{relationship.source_asset_id}:{relationship.relationship_type.value}:{relationship.target_asset_id}",
        }
        await self._execute_write(self._RELATIONSHIP_QUERY, parameters)

    async def get_assets(self, asset_ids: tuple[UUID, ...]) -> tuple[Asset, ...]:
        """Retrieve assets in supplied path order for deterministic scope enforcement."""
        if not asset_ids:
            return ()
        records = await self._execute_read_all(
            self._GET_ASSETS_QUERY, {"asset_ids": [str(asset_id) for asset_id in asset_ids]}
        )
        assets_by_id = {UUID(record["asset"]["asset_id"]): self._to_asset(record["asset"]) for record in records}
        return tuple(assets_by_id[asset_id] for asset_id in asset_ids if asset_id in assets_by_id)

    async def find_shortest_path_to_crown_jewel(
        self, source_asset_id: UUID, *, max_hops: int = 8
    ) -> AttackPath:
        """Find one stable, bounded shortest route using Cypher rather than an LLM."""
        if not 1 <= max_hops <= 8:
            raise ValueError("max_hops must be between 1 and 8")
        parameters: dict[str, object] = {
            "source_asset_id": str(source_asset_id),
            "crown_jewel_types": [AssetType.DATABASE.value, AssetType.SECRET.value],
            "max_hops": max_hops,
        }
        record = await self._execute_read_one(self._SHORTEST_PATH_QUERY, parameters)
        if record is None:
            raise TopologyNotFoundError(f"No crown-jewel path exists for source asset {source_asset_id}")

        path_nodes = record["path_nodes"]
        path_relationships = record["path_relationships"]
        asset_ids = tuple(UUID(node["asset_id"]) for node in path_nodes)
        steps = tuple(
            AttackPathStep(
                source_asset_id=UUID(relationship.start_node["asset_id"]),
                target_asset_id=UUID(relationship.end_node["asset_id"]),
                relationship_type=RelationshipType(relationship["relationship_type"]),
                properties=dict(relationship["properties"]),
            )
            for relationship in path_relationships
        )
        return AttackPath(
            source_asset_id=source_asset_id,
            target_asset_id=asset_ids[-1],
            asset_ids=asset_ids,
            steps=steps,
            hop_count=record["hop_count"],
        )

    async def _execute_write(self, query: str, parameters: Mapping[str, object]) -> None:
        """Validate and execute a write transaction with transient-failure retries."""
        self._validator.validate(query, parameters, CypherIntent.WRITE)

        async def operation() -> None:
            async with self._require_driver().session(database=self._settings.database) as session:
                await session.execute_write(self._run_query, query, parameters)

        await self._execute(operation)

    async def _execute_read_one(self, query: str, parameters: Mapping[str, object]) -> Any | None:
        """Validate and execute a read transaction, returning its first record."""
        self._validator.validate(query, parameters, CypherIntent.READ)

        async def operation() -> Any | None:
            async with self._require_driver().session(database=self._settings.database) as session:
                return await session.execute_read(self._run_query_one, query, parameters)

        return await self._execute(operation)

    async def _execute_read_all(self, query: str, parameters: Mapping[str, object]) -> list[Any]:
        """Validate and execute a read transaction, returning all bounded records."""
        self._validator.validate(query, parameters, CypherIntent.READ)

        async def operation() -> list[Any]:
            async with self._require_driver().session(database=self._settings.database) as session:
                return await session.execute_read(self._run_query_all, query, parameters)

        return await self._execute(operation)

    @staticmethod
    async def _run_query(transaction: AsyncManagedTransaction, query: str, parameters: Mapping[str, object]) -> None:
        """Consume write results so server-side failures are surfaced inside the transaction."""
        result = await transaction.run(query, parameters=dict(parameters))
        await result.consume()

    @staticmethod
    async def _run_query_one(
        transaction: AsyncManagedTransaction, query: str, parameters: Mapping[str, object]
    ) -> Any | None:
        """Return the first record from a read transaction."""
        result = await transaction.run(query, parameters=dict(parameters))
        return await result.single()

    @staticmethod
    async def _run_query_all(
        transaction: AsyncManagedTransaction, query: str, parameters: Mapping[str, object]
    ) -> list[Any]:
        """Return all records from the intentionally bounded asset lookup."""
        result = await transaction.run(query, parameters=dict(parameters))
        return [record async for record in result]

    async def _execute(self, operation: Callable[[], Awaitable[ResultT]]) -> ResultT:
        """Map Neo4j failures to a stable domain exception after retrying transient ones."""
        try:
            return await self._retry(operation)
        except RetryableGraphError as error:
            raise GraphQueryError("Neo4j request failed after transient-error retries") from error
        except Neo4jError as error:
            raise GraphQueryError("Neo4j rejected the graph operation") from error

    @staticmethod
    async def _retry(operation: Callable[[], Awaitable[ResultT]]) -> ResultT:
        """Run an async operation with bounded exponential backoff and jitter."""
        async for attempt in AsyncRetrying(
            retry=retry_if_exception_type(RetryableGraphError),
            wait=wait_exponential_jitter(initial=0.25, max=4.0),
            stop=stop_after_attempt(3),
            reraise=True,
        ):
            with attempt:
                return await operation()
        raise AssertionError("tenacity retry loop completed without returning or raising")

    def _require_driver(self) -> AsyncDriver:
        """Return the initialized driver or fail with an explicit lifecycle error."""
        if self._driver is None:
            raise GraphConnectionError("Neo4j driver is not connected; call connect() first")
        return self._driver

    @staticmethod
    def _asset_parameters(asset: Asset) -> dict[str, object]:
        """Serialize the domain entity without exposing model internals to Neo4j."""
        return {
            "asset_id": str(asset.asset_id),
            "name": asset.name,
            "asset_type": asset.asset_type.value,
            "environment": asset.environment.value,
            "criticality": asset.criticality.value,
            "is_crown_jewel": asset.is_crown_jewel,
            "provider": asset.provider,
            "region": asset.region,
            "tags": asset.tags,
        }

    @staticmethod
    def _to_asset(node: Any) -> Asset:
        """Map a Neo4j node back into the immutable domain entity."""
        return Asset(
            asset_id=UUID(node["asset_id"]),
            name=node["name"],
            asset_type=AssetType(node["asset_type"]),
            environment=node["environment"],
            criticality=node["criticality"],
            is_crown_jewel=node["is_crown_jewel"],
            provider=node["provider"],
            region=node["region"],
            tags=dict(node["tags"]),
        )
