"""Official asynchronous Neo4j adapter for graph topology and path queries."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, LiteralString, Self, TypeVar
from uuid import UUID

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncManagedTransaction
from neo4j.exceptions import DriverError, Neo4jError, ServiceUnavailable, SessionExpired
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from art_sim.blast_radius.calculator import BlastRadiusResult
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
    WITH path, nodes(path) AS path_nodes, relationships(path) AS path_relationships
    RETURN path_nodes, path_relationships, length(path) AS hop_count
    ORDER BY hop_count ASC, [node IN path_nodes | node.asset_id] ASC
    LIMIT 1
    """
    _BLAST_RADIUS_QUERY = """
    MATCH (source:Asset {asset_id: $source_asset_id})
    OPTIONAL MATCH path = (source)-[:TOPOLOGY_EDGE*1..8]->(reachable:Asset)
    WHERE length(path) <= $max_hops
    WITH source, collect(DISTINCT reachable) AS reachable_assets
    MATCH (asset:Asset)
    WHERE asset.asset_id <> source.asset_id
    WITH reachable_assets, collect(asset) AS all_assets
    RETURN size(reachable_assets) AS reachable_assets,
           size(all_assets) AS total_assets,
           size([asset IN reachable_assets WHERE asset.criticality = 'critical']) AS reachable_critical_assets,
           size([asset IN all_assets WHERE asset.criticality = 'critical']) AS total_critical_assets,
           size([asset IN reachable_assets WHERE asset.is_crown_jewel = true]) AS reachable_crown_jewels,
           size([asset IN all_assets WHERE asset.is_crown_jewel = true]) AS total_crown_jewels
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
            driver_kwargs: dict[str, Any] = {
                "auth": (self._settings.username, self._settings.password.get_secret_value()),
                "max_connection_pool_size": self._settings.max_connection_pool_size,
            }

            # Si la URI no usa esquemas con SSL implícito (+s / +ssc), incluimos 'encrypted'
            if not self._settings.uri.startswith(("neo4j+s", "neo4j+ssc", "bolt+s", "bolt+ssc")):
                driver_kwargs["encrypted"] = self._settings.encrypted

            self._driver = AsyncGraphDatabase.driver(
                self._settings.uri,
                **driver_kwargs,
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
            "properties": json.dumps(relationship.properties, sort_keys=True),
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
                properties=self._decode_string_map(relationship["properties"], "relationship properties"),
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

    async def calculate_blast_radius(
        self, source_asset_id: UUID, *, max_hops: int = 8
    ) -> BlastRadiusResult:
        """Aggregate reachability in one bounded, parameterized Neo4j read query."""
        if not 1 <= max_hops <= 8:
            raise ValueError("max_hops must be between 1 and 8")
        record = await self._execute_read_one(
            self._BLAST_RADIUS_QUERY,
            {"source_asset_id": str(source_asset_id), "max_hops": max_hops},
        )
        if record is None:
            raise TopologyNotFoundError(f"No source asset exists for blast radius: {source_asset_id}")
        reachable_assets = record["reachable_assets"]
        total_assets = record["total_assets"]
        reachable_critical_assets = record["reachable_critical_assets"]
        total_critical_assets = record["total_critical_assets"]
        reachable_crown_jewels = record["reachable_crown_jewels"]
        total_crown_jewels = record["total_crown_jewels"]
        if not all(
            isinstance(value, int)
            for value in (
                reachable_assets,
                total_assets,
                reachable_critical_assets,
                total_critical_assets,
                reachable_crown_jewels,
                total_crown_jewels,
            )
        ):
            raise GraphQueryError("Neo4j blast-radius query returned invalid aggregate types")
        return BlastRadiusResult(
            source_asset_id=source_asset_id,
            reachable_assets=reachable_assets,
            total_assets=total_assets,
            reachable_critical_assets=reachable_critical_assets,
            total_critical_assets=total_critical_assets,
            reachable_crown_jewels=reachable_crown_jewels,
            total_crown_jewels=total_crown_jewels,
            blast_radius_percentage=self._percentage(reachable_assets, total_assets),
            critical_blast_radius_percentage=self._percentage(
                reachable_critical_assets, total_critical_assets
            ),
            crown_jewel_exposure_percentage=self._percentage(
                reachable_crown_jewels, total_crown_jewels
            ),
        )

    async def _execute_write(self, query: LiteralString, parameters: Mapping[str, object]) -> None:
        """Validate and execute a write transaction with transient-failure retries."""
        self._validator.validate(query, parameters, CypherIntent.WRITE)

        async def operation() -> None:
            async with self._require_driver().session(database=self._settings.database) as session:
                await session.execute_write(self._run_query, query, parameters)

        await self._execute(operation)

    async def _execute_read_one(self, query: LiteralString, parameters: Mapping[str, object]) -> Any | None:
        """Validate and execute a read transaction, returning its first record."""
        self._validator.validate(query, parameters, CypherIntent.READ)

        async def operation() -> Any | None:
            async with self._require_driver().session(database=self._settings.database) as session:
                return await session.execute_read(self._run_query_one, query, parameters)

        return await self._execute(operation)

    async def _execute_read_all(self, query: LiteralString, parameters: Mapping[str, object]) -> list[Any]:
        """Validate and execute a read transaction, returning all bounded records."""
        self._validator.validate(query, parameters, CypherIntent.READ)

        async def operation() -> list[Any]:
            async with self._require_driver().session(database=self._settings.database) as session:
                return await session.execute_read(self._run_query_all, query, parameters)

        return await self._execute(operation)

    @staticmethod
    async def _run_query(transaction: AsyncManagedTransaction, query: LiteralString, parameters: Mapping[str, object]) -> None:
        """Consume write results so server-side failures are surfaced inside the transaction."""
        result = await transaction.run(query, parameters=dict(parameters))
        await result.consume()

    @staticmethod
    async def _run_query_one(
        transaction: AsyncManagedTransaction, query: LiteralString, parameters: Mapping[str, object]
    ) -> Any | None:
        """Return the first record from a read transaction."""
        result = await transaction.run(query, parameters=dict(parameters))
        return await result.single()

    @staticmethod
    async def _run_query_all(
        transaction: AsyncManagedTransaction, query: LiteralString, parameters: Mapping[str, object]
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
        """Serialize an asset without exposing model internals to Neo4j."""
        return {
            "asset_id": str(asset.asset_id),
            "name": asset.name,
            "asset_type": asset.asset_type.value,
            "environment": asset.environment.value,
            "criticality": asset.criticality.value,
            "is_crown_jewel": asset.is_crown_jewel,
            "provider": asset.provider,
            "region": asset.region,
            "tags": json.dumps(asset.tags, sort_keys=True),
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
            tags=Neo4jGraphRepository._decode_string_map(node["tags"], "asset tags"),
        )

    @staticmethod
    def _decode_string_map(value: object, field_name: str) -> dict[str, str]:
        """Decode the JSON representation required for Neo4j scalar properties."""
        try:
            decoded: object = json.loads(value) if isinstance(value, str) else value
        except (TypeError, ValueError) as error:
            raise GraphQueryError(f"Neo4j {field_name} are not valid JSON object data") from error
        if not isinstance(decoded, Mapping):
            raise GraphQueryError(f"Neo4j {field_name} do not match the expected string map schema")
        string_map: dict[str, str] = {}
        for key, item in decoded.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise GraphQueryError(f"Neo4j {field_name} do not match the expected string map schema")
            string_map[key] = item
        return string_map

    @staticmethod
    def _percentage(numerator: int, denominator: int) -> float:
        """Return a stable percentage while avoiding division by zero."""
        return round((100.0 * numerator / denominator) if denominator else 0.0, 2)
