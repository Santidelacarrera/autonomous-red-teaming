"""Checkpoint deserialization is allow-listed, so a tampered database cannot build arbitrary types."""

from __future__ import annotations

import logging
from enum import Enum

import pytest
from pydantic import BaseModel

from art_sim.agents.models import AttackPlan, PlanStatus
from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.domain.models import Asset, AssetType, Environment
from art_sim.platform.checkpoint import (
    CHECKPOINT_STATE_MODULES,
    allowed_checkpoint_types,
    checkpoint_serde,
)
from art_sim.remediation.state_machine import RemediationLifecycle, SimulationLifecycleState
from art_sim.worker.fixtures import shadow_demo_scenario


def test_allowlist_covers_state_types_and_only_project_modules() -> None:
    allowed = set(allowed_checkpoint_types())
    for expected in (
        ("art_sim.domain.models", "Asset"),
        ("art_sim.agents.models", "AttackPlan"),
        ("art_sim.attack.simulated_graph", "SimulatedAttackGraph"),
        ("art_sim.remediation.state_machine", "RemediationLifecycle"),
        ("art_sim.remediation.state_machine", "SimulationLifecycleState"),
    ):
        assert expected in allowed
    assert {module for module, _ in allowed} <= set(CHECKPOINT_STATE_MODULES)
    # Nothing re-exported from a third-party package sneaks in.
    assert ("pydantic", "BaseModel") not in allowed
    assert all(not module.startswith(("os", "builtins", "subprocess")) for module, _ in allowed)


@pytest.mark.parametrize(
    "value",
    [
        Asset(name="a", asset_type=AssetType.COMPUTE, environment=Environment.SHADOW, provider="synthetic"),
        PlanStatus.DRAFT,
        SimulationLifecycleState.AWAITING_APPROVAL,
        RemediationLifecycle(),
        shadow_demo_scenario().graph,
    ],
    ids=["asset", "enum", "lifecycle-enum", "lifecycle", "graph"],
)
def test_allow_listed_state_round_trips_exactly(value: object) -> None:
    serde = checkpoint_serde()
    restored = serde.loads_typed(serde.dumps_typed(value))
    assert type(restored) is type(value)
    assert restored == value


def test_unlisted_type_is_never_instantiated(caplog: pytest.LogCaptureFixture) -> None:
    class Impostor(BaseModel):
        payload: int = 1

    Impostor.__module__ = "os"  # an importable module outside the allow-list
    serde = checkpoint_serde()
    with caplog.at_level(logging.WARNING):
        restored = serde.loads_typed(serde.dumps_typed(Impostor()))
    assert not isinstance(restored, Impostor)
    assert restored == {"payload": 1}  # inert data, not an object
    assert "Blocked deserialization" in caplog.text


def test_unlisted_enum_is_blocked_too(caplog: pytest.LogCaptureFixture) -> None:
    class Level(Enum):
        HIGH = "high"

    Level.__module__ = "os"
    serde = checkpoint_serde()
    with caplog.at_level(logging.WARNING):
        restored = serde.loads_typed(serde.dumps_typed(Level.HIGH))
    assert not isinstance(restored, Level)


def test_graph_state_types_are_all_listed() -> None:
    """Guards the derivation: the field types of the checkpointed state must stay allowed."""
    allowed = {name for _, name in allowed_checkpoint_types()}
    assert {AttackPlan.__name__, SimulatedAttackGraph.__name__, "AssetRelationship", "AttackPath"} <= allowed
