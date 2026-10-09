"""Drive the real application stack through the laboratory scenario and collect evidence.

Nothing in this module re-implements product logic. It composes the production FastAPI app
(``create_app``) over the SQLite operational store, a real ``SimulationWorker`` with a durable
LangGraph checkpointer and HMAC approval signing, and the hash-chained audit sink, then talks
to the app over ASGI exactly as a client would: create a simulation, let the worker pause at
the human gate, try (and fail) to bypass the gate in several ways, approve as an authorized
operator, resume, and read the verified result. Every control exercised is recorded with the
status the API actually returned, so the report is evidence, not narration.
"""

from __future__ import annotations

import secrets
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from art_sim.adapters.jsonl_audit_sink import JsonlDurableSecurityAuditSink
from art_sim.api.app import create_app
from art_sim.api.security import DevelopmentHeaderAuthenticator
from art_sim.api.services import (
    ApprovalService,
    CancellationService,
    ScenarioCatalog,
    SimulationResultService,
    SimulationReviewService,
    SimulationService,
)
from art_sim.attack.explain import RiskExplanation, explain_risk
from art_sim.demo.lab import LAB_SCENARIO_ID, lab_scenario
from art_sim.domain.models import AssetRelationship, AttackPath
from art_sim.platform.checkpoint import sqlite_langgraph_checkpointer
from art_sim.platform.health import HealthService
from art_sim.platform.models import AuditEvent, SimulationRun, SimulationRunStatus
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import AuditRetentionPolicy, SecurityAuditEvent
from art_sim.security.audit_chain import (
    AuditVerificationReport,
    durable_event_ids,
    verify_audit_log,
)
from art_sim.worker.models import SimulationArtifacts, SimulationReview, SimulationScenario
from art_sim.worker.shadow import InMemoryScenarioRepository
from art_sim.worker.worker import SimulationWorker, WorkerRunResult
from art_sim.worker.workflow import DurableSimulationWorkflow

MARKER = ".art-sim-demo"
APPROVAL_TTL = timedelta(hours=24)

# Identities: development bearer tokens `development:<role>:<subject>#<organization>`.
OPERATOR = "Bearer development:operator:alice#acme"
VIEWER = "Bearer development:viewer:vera#acme"
ADMIN = "Bearer development:admin:ada#acme"
OUTSIDER = "Bearer development:admin:mallory#globex"
APPROVE_BODY = {
    "decision": "approved",
    "reason": "Reviewed the simulated countermeasure: severs the container-escape step.",
}

Narrate = Callable[[str], None]


class DemoInvariantError(RuntimeError):
    """The demonstration reached a state that contradicts the product's guarantees."""


def _require(condition: bool, message: str) -> None:
    """Fail loudly. Unlike ``assert`` this still runs under ``python -O``, and the demo's
    claims (the gate was not bypassed, the worker paused where it must) are the whole point."""
    if not condition:
        raise DemoInvariantError(message)


class _Clock:
    """Wall clock the demo can advance to show a review window closing."""

    def __init__(self) -> None:
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now


@dataclass(frozen=True)
class ControlCheck:
    """One control exercised against the live app, with what was expected and observed."""

    control: str
    request: str
    actor: str
    expected: int
    observed: int
    effect: str

    @property
    def passed(self) -> bool:
        """The control held when the API answered exactly as the policy requires."""
        return self.expected == self.observed


@dataclass
class DemoEvidence:
    """Everything the report needs; produced once by ``run_lab``."""

    scenario: SimulationScenario
    path: AttackPath
    removed_edge: AssetRelationship
    review: SimulationReview
    result: SimulationArtifacts
    explanation: RiskExplanation
    run: SimulationRun
    operational_events: tuple[AuditEvent, ...]
    security_events: tuple[SecurityAuditEvent, ...]
    audit_report: AuditVerificationReport
    tamper_report: AuditVerificationReport
    audit_path: Path
    controls: list[ControlCheck] = field(default_factory=list)
    expired_run: SimulationRun | None = None


def prepare_output(out: Path) -> None:
    """Create ``out`` for the demo, wiping only a directory a previous demo run created."""
    if out.exists() and any(out.iterdir()):
        if not (out / MARKER).exists():
            raise FileExistsError(
                f"{out} exists, is not empty and was not created by the demo; refusing to "
                "overwrite it. Choose another --out directory."
            )
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / MARKER).write_text("created by `python -m art_sim.demo`; safe to delete\n")


async def _healthy() -> None:
    """The demo's only dependencies are in-process."""


async def run_lab(out: Path, narrate: Narrate = lambda _: None) -> DemoEvidence:
    """Execute the whole scenario and return the collected evidence."""
    scenario = lab_scenario()
    graph = scenario.graph
    state_dir = out / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    database = state_dir / "operations.sqlite3"
    audit_path = out / "audit" / "security.jsonl"

    clock = _Clock()
    store = SqliteOperationalStore(database, clock=clock, approval_ttl=APPROVAL_TTL)
    await store.initialize()
    audit_sink = JsonlDurableSecurityAuditSink(audit_path, AuditRetentionPolicy(retention_days=365))
    app = create_app(
        SimulationService(store, ScenarioCatalog((LAB_SCENARIO_ID,))),
        ApprovalService(store),
        HealthService({"store": _healthy}),
        DevelopmentHeaderAuthenticator(enabled=True),
        security_audit=audit_sink,
        result_service=SimulationResultService(store),
        review_service=SimulationReviewService(store),
        cancellation_service=CancellationService(store),
    )
    signing_secret = secrets.token_bytes(32)  # per-execution; never written anywhere
    controls: list[ControlCheck] = []

    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://lab.local") as api,
        sqlite_langgraph_checkpointer(database) as saver,
    ):
        worker = SimulationWorker(
            store,
            ScenarioCatalog((LAB_SCENARIO_ID,)),
            InMemoryScenarioRepository((scenario,)),
            DurableSimulationWorkflow(saver, signing_secret),
            owner_id="demo-worker",
        )

        async def call(
            control: str, actor: str, method: str, path: str, expected: int, effect: str,
            *, body: dict[str, Any] | None = None, label: str = "",
        ) -> httpx.Response:
            headers = {"Authorization": actor} if actor else {}
            response = await api.request(method, path, headers=headers, json=body)
            who = actor.split(":", 1)[-1] if actor else "anonymous"
            check = ControlCheck(control, f"{method} {label or path}", who, expected, response.status_code, effect)
            controls.append(check)
            narrate(f"    {'✓' if check.passed else '✗'} {control}: {check.request} as {who} -> "
                    f"{response.status_code} (expected {expected})")
            return response

        # -------------------------------------------------------------- 1. create + analyze
        narrate("[1/6] Operator alice (org acme) submits the allow-listed lab scenario")
        created = await call(
            "Create simulation (operator)", OPERATOR, "POST", "/api/v1/simulations", 202,
            "run accepted", body={"scenario_id": LAB_SCENARIO_ID},
        )
        run_id = UUID(created.json()["run_id"])
        narrate("[2/6] Worker analyzes the graph, scores risk and pauses at the human gate")
        outcome = await worker.run(run_id)
        _require(outcome is WorkerRunResult.WAITING_APPROVAL, f"worker returned {outcome}")
        run_path = f"/api/v1/simulations/{run_id}"
        review_response = await call(
            "Read review package (viewer)", VIEWER, "GET", f"{run_path}/review", 200,
            "reviewer sees evidence", label="/{run}/review",
        )
        review = SimulationReview.model_validate(review_response.json())

        # -------------------------------------------------------------- 2. try to bypass the gate
        narrate("[3/6] Attempts to bypass the human gate (all must be refused)")
        approve_path = f"{run_path}/approval"
        for control, actor, expected, effect, body in (
            ("Anonymous approval", "", 401, "no identity, no decision", APPROVE_BODY),
            ("Viewer approval", VIEWER, 403, "role lacks simulation:approve", APPROVE_BODY),
            ("Foreign-organization admin approval", OUTSIDER, 404, "run invisible outside its org", APPROVE_BODY),
            ("Approval without a real review reason", OPERATOR, 422, "reason below the review bar",
             {"decision": "approved", "reason": "ok"}),
        ):
            await call(control, actor, "POST", approve_path, expected, effect, body=body,
                       label="/{run}/approval")
        await call("Result read before approval", OPERATOR, "GET", f"{run_path}/report", 409,
                   "no result exists until a human decides", label="/{run}/report")
        await call("Cross-organization read", OUTSIDER, "GET", run_path, 404,
                   "foreign run indistinguishable from missing", label="/{run}")
        gated = await store.get_run(run_id)
        _require(gated.status is SimulationRunStatus.WAITING_APPROVAL, "the human gate was bypassed")

        # -------------------------------------------------------------- 3. human approval
        narrate("[4/6] Authorized operator alice approves the countermeasure")
        await call("Operator approval", OPERATOR, "POST", approve_path, 200,
                   "decision recorded atomically", body=APPROVE_BODY, label="/{run}/approval")
        narrate("[5/6] Worker verifies the HMAC-signed approval, applies it to a graph copy, publishes")
        outcome = await worker.run(run_id)
        _require(outcome is WorkerRunResult.SUCCEEDED, f"worker returned {outcome}")
        await call("Replayed approval", OPERATOR, "POST", approve_path, 409,
                   "first decision is final", body=APPROVE_BODY, label="/{run}/approval")
        await call("Read verified report (viewer)", VIEWER, "GET", f"{run_path}/report", 200,
                   "result now available", label="/{run}/report")
        await call("Read audit trail (operator)", OPERATOR, "GET", f"{run_path}/events", 403,
                   "audit trail is admin-only", label="/{run}/events")
        await call("Read audit trail (admin)", ADMIN, "GET", f"{run_path}/events", 200,
                   "admin can inspect evidence", label="/{run}/events")

        # -------------------------------------------------------------- 4. expiry on a second run
        narrate("[6/6] A second run waits past its 24 h review window: late approval must fail")
        second = await call("Create second simulation", OPERATOR, "POST", "/api/v1/simulations", 202,
                            "run accepted", body={"scenario_id": LAB_SCENARIO_ID})
        second_id = UUID(second.json()["run_id"])
        second_outcome = await worker.run(second_id)
        _require(second_outcome is WorkerRunResult.WAITING_APPROVAL, f"worker returned {second_outcome}")
        clock.now += APPROVAL_TTL + timedelta(minutes=1)
        second_path = f"/api/v1/simulations/{second_id}"
        await call("Approval after the window closed", OPERATOR, "POST", f"{second_path}/approval", 410,
                   "expired decision refused", body=APPROVE_BODY, label="/{run}/approval")
        expired_run = await store.get_run(second_id)
        _require(
            expired_run.status is SimulationRunStatus.WAITING_APPROVAL,
            "an expired approval changed the run",
        )
        await call("Cancel the expired run", OPERATOR, "POST", f"{second_path}/cancel", 200,
                   "stale review is retired, never auto-approved", label="/{run}/cancel")
        expired_run = await store.get_run(second_id)

        final_run = await store.get_run(run_id)
        result = await store.get_result(run_id)
        events = await store.list_events(run_id)

    # ------------------------------------------------------------------ 5. audit integrity
    security_events = await audit_sink.recent(limit=200)
    audit_report = verify_audit_log(audit_path)
    # Show detection: delete one event from a *copy* and verify again.
    tampered = out / "audit" / "security.tampered-demo.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    tampered.write_text("\n".join(lines[:3] + lines[4:]) + "\n", encoding="utf-8")
    tamper_report = verify_audit_log(tampered)
    _require(bool(durable_event_ids(audit_path)), "the audit log is empty")

    removed = _removed_edge(review)
    explanation = explain_risk(review.attack_path, graph.assets, review.risk)
    return DemoEvidence(
        scenario=scenario,
        path=review.attack_path,
        removed_edge=removed,
        review=review,
        result=result,
        explanation=explanation,
        run=final_run,
        operational_events=events,
        security_events=tuple(reversed(security_events)),
        audit_report=audit_report,
        tamper_report=tamper_report,
        audit_path=audit_path,
        controls=controls,
        expired_run=expired_run,
    )


def _removed_edge(review: SimulationReview) -> AssetRelationship:
    """The modeled relation the approved remediation severs, taken from the review package."""
    remediation = review.remediation
    return AssetRelationship(
        source_asset_id=remediation.source_asset_id,
        target_asset_id=remediation.target_asset_id,
        relationship_type=remediation.relationship_type,
    )
