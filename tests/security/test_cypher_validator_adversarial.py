"""Adversarial coverage for the Cypher boundary: every injection attempt must fail closed,
and every real production query must still pass the hardened validator."""

from __future__ import annotations

import pytest

from art_sim.domain.exceptions import CypherValidationError
from art_sim.infrastructure.cypher_validator import CypherIntent, CypherValidator
from art_sim.infrastructure.neo4j_graph_repository import Neo4jGraphRepository

VALIDATOR = CypherValidator()

# The exact static queries the adapter runs, with a representative parameter set each.
PRODUCTION_READS = [
    (Neo4jGraphRepository._GET_ASSETS_QUERY, {"asset_ids": ["a"]}),
    (
        Neo4jGraphRepository._SHORTEST_PATH_QUERY,
        {"source_asset_id": "s", "crown_jewel_types": ["database"], "max_hops": 8},
    ),
    (Neo4jGraphRepository._BLAST_RADIUS_QUERY, {"source_asset_id": "s", "max_hops": 8}),
]
PRODUCTION_WRITES = [
    (
        Neo4jGraphRepository._ASSET_QUERY,
        {
            "asset_id": "a",
            "name": "n",
            "asset_type": "t",
            "environment": "e",
            "criticality": "c",
            "is_crown_jewel": False,
            "provider": "p",
            "region": "r",
            "tags": "{}",
        },
    ),
    (
        Neo4jGraphRepository._IDENTITY_QUERY,
        {
            "identity_id": "i",
            "principal": "p",
            "provider": "k",
            "environment": "e",
            "is_privileged": False,
            "roles": [],
        },
    ),
    (
        Neo4jGraphRepository._RELATIONSHIP_QUERY,
        {
            "source_asset_id": "s",
            "target_asset_id": "t",
            "relationship_type": "rt",
            "properties": "{}",
            "edge_key": "k",
        },
    ),
]

INJECTION_ATTEMPTS = [
    "MATCH (a) RETURN a; DROP DATABASE neo4j",
    "MATCH (a) RETURN a // comment",
    "MATCH (a) RETURN a /* block */",
    "CALL dbms.components() YIELD name RETURN name",
    "CALL apoc.cypher.run('MATCH (n) DETACH DELETE n', {})",
    "MATCH (a) DETACH DELETE a",
    "MATCH (a) DELETE a",
    "LOAD CSV FROM 'http://evil/x.csv' AS row RETURN row",
    "CREATE (x:Admin {name:'root'})",
    "MATCH (a) CREATE (b:Backdoor)",
    "MATCH (a) SET a.is_crown_jewel = false RETURN a",
    "MATCH (a) REMOVE a:Asset RETURN a",
    "SHOW DATABASES",
    "USE system MATCH (a) RETURN a",
    "GRANT ROLE admin TO user",
    "DENY ALL ON DATABASE neo4j TO user",
    "REVOKE ROLE admin FROM user",
    "DROP INDEX asset_id_index",
    "MATCH (a) FOREACH (x IN [1] | SET a.p = 1) RETURN a",
    "TERMINATE TRANSACTIONS 'transaction-1'",
    "   ",
    "",
    "RETURN 1",  # does not start with an allowed clause
    "WITH 1 AS x RETURN x",  # read must start with MATCH/OPTIONAL MATCH/UNWIND
]


@pytest.mark.parametrize("query,parameters", PRODUCTION_READS)
def test_real_read_queries_pass(query: str, parameters: dict[str, object]) -> None:
    VALIDATOR.validate(query, parameters, CypherIntent.READ)


@pytest.mark.parametrize("query,parameters", PRODUCTION_WRITES)
def test_real_write_queries_pass(query: str, parameters: dict[str, object]) -> None:
    VALIDATOR.validate(query, parameters, CypherIntent.WRITE)


@pytest.mark.parametrize("payload", INJECTION_ATTEMPTS)
def test_injection_attempts_are_rejected_for_reads(payload: str) -> None:
    with pytest.raises(CypherValidationError):
        VALIDATOR.validate(payload, {}, CypherIntent.READ)


def test_write_clause_is_rejected_under_read_intent() -> None:
    with pytest.raises(CypherValidationError, match="write clauses"):
        VALIDATOR.validate("MATCH (a) SET a.x = 1 RETURN a", {}, CypherIntent.READ)


def test_missing_parameters_are_rejected() -> None:
    with pytest.raises(CypherValidationError, match="missing parameters"):
        VALIDATOR.validate("MATCH (a {id: $id}) RETURN a", {}, CypherIntent.READ)


def test_write_without_write_start_is_rejected() -> None:
    with pytest.raises(CypherValidationError):
        VALIDATOR.validate("RETURN 1", {}, CypherIntent.WRITE)
