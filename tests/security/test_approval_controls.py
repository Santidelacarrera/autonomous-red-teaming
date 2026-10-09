"""High-impact actions require a valid human approval: positive and negative controls.

Covers, end to end through the HTTP boundary and the durable store:

* a correct approval inside the review window succeeds and is audited;
* expired approvals, insufficient permissions and replayed requests are refused;
* every refusal leaves the persisted simulation exactly as it was;
* approval proofs (HMAC) bind decision, operator, run and time — wrong signatures,
  forged records, replayed proofs and rotated secrets are all rejected.

Everything runs against synthetic Shadow data; nothing reaches real infrastructure.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import ApprovalService, ScenarioCatalog, SimulationService
from art_sim.attack.risk import RiskScorer
from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.domain.exceptions import (
    ApprovalExpiredError,
    ApprovalRequiredError,
    ConfigurationError,
)
from art_sim.domain.models import (
    Asset,
    AssetRelationship,
    AssetType,
    Criticality,
    Environment,
    RelationshipType,
)
from art_sim.platform.health import HealthService
from art_sim.platform.models import SimulationRun, SimulationRunStatus
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.remediation.approval import HumanApprovalWorkflow, RemediationFlowState
from art_sim.remediation.models import (
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStatus,
    NormalizedRemediation,
)
from art_sim.remediation.normalization import RemediationPlanner
from art_sim.remediation.verification import RemediationVerifier
from art_sim.security.audit import InMemorySecurityAuditSink, SecurityEventType

TTL = timedelta(minutes=30)
OPERATOR = {"Authorization": "Bearer development:operator:alice"}
VIEWER = {"Authorization": "Bearer development:viewer:bob"}
APPROVE = {"decision": "approved", "reason": "Reviewed the simulated countermeasure evidence."}
REJECT = {"decision": "rejected", "reason": "Operational change window is not available."}


class _Clock:
    """Mutable wall clock so tests can move past the review window deterministically."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


async def _healthy() -> None:
    """Deterministic readiness dependency."""


class _Harness:
    def __init__(
        self, client: TestClient, store: SqliteOperationalStore, clock: _Clock, audit: InMemorySecurityAuditSink
    ) -> None:
        self.client, self.store, self.clock, self.audit = client, store, clock, audit

    async def waiting_run(self) -> UUID:
        """Create a run through the API and park it in WAITING_APPROVAL as a worker would."""
        created = self.client.post(
            "/api/v1/simulations", headers=OPERATOR, json={"scenario_id": "shadow-demo"}
        )
        assert created.status_code == 202
        run_id = UUID(created.json()["run_id"])
        claim = await self.store.acquire_execution(run_id, "control-test", UUID(int=1))
        assert claim is not None
        await self.store.mark_waiting_approval(run_id, "control-test", claim.fencing_token)
        return run_id

    def decide(self, run_id: UUID, headers: dict[str, str], body: dict[str, str]) -> Any:
        return self.client.post(f"/api/v1/simulations/{run_id}/approval", headers=headers, json=body)


async def _harness(tmp_path: Path, *, ttl: timedelta | None = TTL) -> _Harness:
    clock = _Clock()
    store = SqliteOperationalStore(tmp_path / "controls.sqlite3", clock=clock, approval_ttl=ttl)
    await store.initialize()
    audit = InMemorySecurityAuditSink()
    app = create_app(
        SimulationService(store, ScenarioCatalog(("shadow-demo",))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_audit=audit,
    )
    return _Harness(TestClient(app), store, clock, audit)


async def _audit_types(harness: _Harness) -> list[SecurityEventType]:
    return [event.event_type for event in await harness.audit.recent(limit=200)]


# --------------------------------------------------------------------- positive control


async def test_valid_approval_inside_the_window_succeeds_and_is_audited(tmp_path: Path) -> None:
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    h.clock.advance(TTL - timedelta(seconds=1))

    response = h.decide(run_id, OPERATOR, APPROVE)

    assert response.status_code == 200
    body = response.json()
    assert body["approval_status"] == "approved"
    assert body["approval_actor"] == "alice"
    assert body["status"] == "resuming"
    assert SecurityEventType.APPROVAL_APPROVED in await _audit_types(h)
    persisted = await h.store.list_events(run_id)
    assert [e.event_type for e in persisted][-1] == "simulation.approved"
    assert persisted[-1].actor == "alice"


async def test_window_boundary_is_inclusive(tmp_path: Path) -> None:
    """Exactly TTL after the review was requested is still valid; one tick later is not."""
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    h.clock.advance(TTL)
    assert h.decide(run_id, OPERATOR, APPROVE).status_code == 200

    other = await h.waiting_run()
    h.clock.advance(TTL + timedelta(microseconds=1))
    assert h.decide(other, OPERATOR, APPROVE).status_code == 410


# --------------------------------------------------------------------- expired approvals


@pytest.mark.parametrize("body", [APPROVE, REJECT], ids=["approve", "reject"])
async def test_expired_decision_is_refused_and_leaves_the_run_untouched(
    tmp_path: Path, body: dict[str, str]
) -> None:
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    before = await h.store.get_run(run_id)
    events_before = await h.store.list_events(run_id)
    h.clock.advance(TTL + timedelta(minutes=1))

    response = h.decide(run_id, OPERATOR, body)

    assert response.status_code == 410
    assert response.json()["error"]["code"] == "APPROVAL_EXPIRED"
    assert await h.store.get_run(run_id) == before  # no status, actor, reason or timestamp change
    assert await h.store.list_events(run_id) == events_before
    assert before.status is SimulationRunStatus.WAITING_APPROVAL
    assert before.approval_status is ApprovalStatus.PENDING
    types = await _audit_types(h)
    assert SecurityEventType.APPROVAL_EXPIRED in types
    assert SecurityEventType.APPROVAL_APPROVED not in types
    assert SecurityEventType.APPROVAL_REJECTED not in types


async def test_expired_run_can_still_be_cancelled(tmp_path: Path) -> None:
    """Expiry must not strand a run: the review window closes, cancellation stays available."""
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    h.clock.advance(TTL * 2)
    assert h.decide(run_id, OPERATOR, APPROVE).status_code == 410
    cancelled = await h.store.request_cancellation(run_id, "alice")
    assert cancelled.status is SimulationRunStatus.CANCELLED


async def test_store_raises_a_typed_error_that_still_counts_as_approval_failure(
    tmp_path: Path,
) -> None:
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    h.clock.advance(TTL * 2)
    with pytest.raises(ApprovalExpiredError) as caught:
        await h.store.decide(run_id, ApprovalDecision.APPROVED, "alice", "Reviewed in detail.")
    assert isinstance(caught.value, ApprovalRequiredError)  # existing fail-closed handlers apply


async def test_store_without_a_ttl_keeps_the_legacy_open_window(tmp_path: Path) -> None:
    h = await _harness(tmp_path, ttl=None)
    run_id = await h.waiting_run()
    h.clock.advance(timedelta(days=400))
    assert h.decide(run_id, OPERATOR, APPROVE).status_code == 200


def test_non_positive_ttl_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        SqliteOperationalStore(tmp_path / "x.sqlite3", approval_ttl=timedelta(0))


# ------------------------------------------------------------ insufficient permissions


@pytest.mark.parametrize("body", [APPROVE, REJECT], ids=["approve", "reject"])
async def test_viewer_cannot_decide_and_run_is_unchanged(
    tmp_path: Path, body: dict[str, str]
) -> None:
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    before = await h.store.get_run(run_id)

    response = h.decide(run_id, VIEWER, body)

    assert response.status_code == 403
    assert await h.store.get_run(run_id) == before
    assert SecurityEventType.AUTHORIZATION_DENIED in await _audit_types(h)


async def test_unauthenticated_and_malformed_credentials_cannot_decide(tmp_path: Path) -> None:
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    before = await h.store.get_run(run_id)
    assert h.decide(run_id, {}, APPROVE).status_code == 401
    bad = {"Authorization": "Bearer development:superuser:mallory"}
    assert h.decide(run_id, bad, APPROVE).status_code == 401
    assert await h.store.get_run(run_id) == before


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "approved", "reason": "short"},  # reason below the 10-char review bar
        {"decision": "maybe", "reason": "Reviewed the simulated countermeasure."},
        {"decision": "approved", "reason": "Reviewed.", "actor": "someone-else"},  # forged field
    ],
    ids=["short-reason", "unknown-decision", "extra-field"],
)
async def test_malformed_decisions_are_rejected_before_touching_state(
    tmp_path: Path, body: dict[str, str]
) -> None:
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    before = await h.store.get_run(run_id)
    assert h.decide(run_id, OPERATOR, body).status_code == 422
    assert await h.store.get_run(run_id) == before


# ----------------------------------------------------------------------------- replay


async def test_replayed_decision_is_rejected_and_first_decision_is_preserved(
    tmp_path: Path,
) -> None:
    h = await _harness(tmp_path)
    run_id = await h.waiting_run()
    assert h.decide(run_id, OPERATOR, APPROVE).status_code == 200
    decided = await h.store.get_run(run_id)

    # Exact replay, and a conflicting decision from a second operator, both bounce.
    assert h.decide(run_id, OPERATOR, APPROVE).status_code == 409
    second = {"Authorization": "Bearer development:operator:carol"}
    assert h.decide(run_id, second, REJECT).status_code == 409

    assert await h.store.get_run(run_id) == decided
    assert decided.approval_actor == "alice"
    assert decided.approval_status is ApprovalStatus.APPROVED
    approvals = [e for e in await h.store.list_events(run_id) if e.event_type.startswith("simulation.a")]
    assert len(approvals) == 1


async def test_decision_before_the_run_is_waiting_is_refused(tmp_path: Path) -> None:
    """Approval cannot be pre-recorded for a run that has not reached its review gate."""
    h = await _harness(tmp_path)
    created = h.client.post("/api/v1/simulations", headers=OPERATOR, json={"scenario_id": "shadow-demo"})
    run_id = UUID(created.json()["run_id"])
    before = await h.store.get_run(run_id)
    assert before.status is SimulationRunStatus.CREATED
    assert h.decide(run_id, OPERATOR, APPROVE).status_code == 409
    assert await h.store.get_run(run_id) == before


# ------------------------------------------------------------- HMAC proof integrity


def _graph() -> SimulatedAttackGraph:
    def asset(n: int, crown: bool = False) -> Asset:
        return Asset(
            asset_id=UUID(int=n),
            name=f"shadow-{n}",
            asset_type=AssetType.DATABASE if crown else AssetType.COMPUTE,
            environment=Environment.SHADOW,
            criticality=Criticality.CRITICAL if crown else Criticality.MEDIUM,
            is_crown_jewel=crown,
            provider="synthetic",
        )

    return SimulatedAttackGraph(
        assets=(asset(1), asset(2), asset(3, crown=True)),
        relationships=(
            AssetRelationship(
                source_asset_id=UUID(int=1),
                target_asset_id=UUID(int=2),
                relationship_type=RelationshipType.CONTAINER_ESCAPE,
            ),
            AssetRelationship(
                source_asset_id=UUID(int=2),
                target_asset_id=UUID(int=3),
                relationship_type=RelationshipType.ACCESS,
            ),
        ),
    )


def _proposal(graph: SimulatedAttackGraph) -> tuple[NormalizedRemediation, float]:
    path = graph.find_shortest_path_to_crown_jewel(UUID(int=1))
    assessment = RiskScorer().assess(path, graph.assets)
    return RemediationPlanner().propose(path, assessment), assessment.score


def _state(run_id: UUID) -> RemediationFlowState:
    graph = _graph()
    proposal, score = _proposal(graph)
    return RemediationFlowState(
        run_id=run_id,
        source_asset_id=UUID(int=1),
        simulated_graph=graph,
        remediation=proposal,
        risk_score=score,
        approval_required=True,
        approval_status=ApprovalStatus.PENDING,
    )


SECRET = b"s" * 32


async def _approved_state(
    workflow: HumanApprovalWorkflow, run_id: UUID, decision: ApprovalDecision
) -> RemediationFlowState:
    """Drive a workflow to a signed decision and return the checkpointed state."""
    await workflow.start(_state(run_id))
    await workflow.decide(run_id, decision=decision, operator="alice", reason="Reviewed evidence.")
    values = await workflow.current(run_id)
    assert values is not None
    return cast(RemediationFlowState, values)


async def test_valid_proof_unlocks_simulated_verification() -> None:
    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=SECRET)
    state = await _approved_state(workflow, uuid4(), ApprovalDecision.APPROVED)
    assert state["approval_status"] is ApprovalStatus.APPROVED
    assert state["verification_result"].status.value == "verified"


@pytest.mark.parametrize("proof", ["", "0" * 64, "not-hex", "A" * 64])
async def test_wrong_signature_is_rejected(proof: str) -> None:
    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=SECRET)
    state = await _approved_state(workflow, uuid4(), ApprovalDecision.APPROVED)
    state["approval_proof"] = proof
    with pytest.raises(ApprovalRequiredError):
        workflow._verification(state)


async def test_missing_proof_or_record_is_rejected() -> None:
    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=SECRET)
    state = await _approved_state(workflow, uuid4(), ApprovalDecision.APPROVED)
    no_proof = cast(RemediationFlowState, {k: v for k, v in state.items() if k != "approval_proof"})
    no_record = cast(RemediationFlowState, {k: v for k, v in state.items() if k != "approval_record"})
    for broken in (no_proof, no_record):
        with pytest.raises(ApprovalRequiredError):
            workflow._verification(broken)


@pytest.mark.parametrize(
    "tamper",
    [
        lambda record: record.model_copy(update={"operator": "mallory"}),
        lambda record: record.model_copy(update={"decided_at": record.decided_at + timedelta(seconds=1)}),
        lambda record: record.model_copy(update={"remediation_id": uuid4()}),
    ],
    ids=["operator-swapped", "timestamp-shifted", "remediation-swapped"],
)
async def test_tampered_approval_record_invalidates_the_proof(
    tamper: object,
) -> None:
    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=SECRET)
    state = await _approved_state(workflow, uuid4(), ApprovalDecision.APPROVED)
    record = state["approval_record"]
    forged = tamper(record)  # type: ignore[operator]
    state["approval_record"] = forged
    with pytest.raises(ApprovalRequiredError):
        workflow._verification(state)


async def test_a_rejection_proof_cannot_be_flipped_into_an_approval() -> None:
    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=SECRET)
    run_id = uuid4()
    rejected = await _approved_state(workflow, run_id, ApprovalDecision.REJECTED)
    assert "verification_result" not in rejected
    record: ApprovalRecord = rejected["approval_record"]
    forged = rejected.copy()
    forged["approval_status"] = ApprovalStatus.APPROVED
    forged["approval_record"] = record.model_copy(update={"decision": ApprovalDecision.APPROVED})
    with pytest.raises(ApprovalRequiredError):
        workflow._verification(forged)


async def test_proof_from_another_run_cannot_be_replayed() -> None:
    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=SECRET)
    legit = await _approved_state(workflow, uuid4(), ApprovalDecision.APPROVED)
    victim_run = uuid4()
    victim = _state(victim_run)
    victim["approval_status"] = ApprovalStatus.APPROVED
    victim["approval_record"] = legit["approval_record"]
    victim["approval_proof"] = legit["approval_proof"]
    victim["lifecycle"] = legit["lifecycle"]
    with pytest.raises(ApprovalRequiredError):
        workflow._verification(victim)


async def test_rotated_or_foreign_signing_secret_cannot_resume_a_signed_decision() -> None:
    """Every replica must use the same secret: a different key rejects, never re-signs."""
    from langgraph.checkpoint.memory import MemorySaver

    saver = MemorySaver()
    run_id = uuid4()
    signer = HumanApprovalWorkflow(RemediationVerifier(), checkpointer=saver, approval_secret=SECRET)
    await _approved_state(signer, run_id, ApprovalDecision.APPROVED)

    imposter = HumanApprovalWorkflow(
        RemediationVerifier(), checkpointer=saver, approval_secret=b"x" * 32
    )
    with pytest.raises(ApprovalRequiredError):
        await imposter.resume_recorded_decision(
            run_id, decision=ApprovalDecision.APPROVED, operator="alice", reason="Reviewed evidence."
        )
    # The legitimate secret still recovers the exact same decision (idempotent, no re-sign).
    again = await signer.resume_recorded_decision(
        run_id, decision=ApprovalDecision.APPROVED, operator="alice", reason="Reviewed evidence."
    )
    assert again["approval_status"] is ApprovalStatus.APPROVED
    # ...but not a different decision or operator.
    for decision, operator in (
        (ApprovalDecision.REJECTED, "alice"),
        (ApprovalDecision.APPROVED, "mallory"),
    ):
        with pytest.raises(ApprovalRequiredError):
            await signer.resume_recorded_decision(
                run_id, decision=decision, operator=operator, reason="Reviewed evidence."
            )


def test_short_signing_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        HumanApprovalWorkflow(RemediationVerifier(), approval_secret=b"too-short")


def test_run_model_carries_review_window_anchor() -> None:
    """The anchor is persisted state, not recomputed, so a restart cannot extend a window."""
    run = SimulationRun(
        scenario_id="shadow-demo", graph_version="v", workflow_version="v1", created_by="alice"
    )
    assert run.approval_requested_at is None
    assert run.organization_id == "default"
