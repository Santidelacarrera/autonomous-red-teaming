"""Domain-model invariants."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from art_sim.domain.models import AssetRelationship, RelationshipType


def test_relationship_rejects_self_loop() -> None:
    """Self-referential topology links are invalid."""
    asset_id = uuid4()
    with pytest.raises(ValidationError, match="must differ"):
        AssetRelationship(
            source_asset_id=asset_id,
            target_asset_id=asset_id,
            relationship_type=RelationshipType.TRUSTS,
        )
