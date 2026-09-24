"""Safety policy tests for the Cypher boundary."""

import pytest

from art_sim.domain.exceptions import CypherValidationError
from art_sim.infrastructure.cypher_validator import CypherIntent, CypherValidator


def test_validator_accepts_parameterized_read() -> None:
    """A parameterized topology read is allowed."""
    CypherValidator().validate("MATCH (asset:Asset {asset_id: $asset_id}) RETURN asset", {"asset_id": "a"}, CypherIntent.READ)


def test_validator_accepts_parameterized_unwind_read() -> None:
    """Ordered asset lookup uses UNWIND but remains a parameterized read-only query."""
    CypherValidator().validate(
        "UNWIND $asset_ids AS asset_id MATCH (asset:Asset {asset_id: asset_id}) RETURN asset",
        {"asset_ids": ["a"]},
        CypherIntent.READ,
    )


def test_validator_rejects_procedure_invocation() -> None:
    """Procedures are prohibited at the graph boundary."""
    with pytest.raises(CypherValidationError, match="prohibited"):
        CypherValidator().validate("CALL db.labels()", {}, CypherIntent.READ)
