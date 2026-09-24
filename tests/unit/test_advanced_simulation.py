"""Deterministic Phase 3-5 coverage for the advanced simulated security workflow."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from art_sim.attack.risk import RiskScorer, RiskScoringSettings
from art_sim.attack.simulated_graph import SimulatedAttackGraph
from art_sim.blast_radius.calculator import BlastRadiusCalculator
from art_sim.domain.exceptions import TopologyNotFoundError
from art_sim.domain.models import (
    Asset,
    AssetRelationship,
    AssetType,
    Criticality,
    Environment,
    RelationshipType,
    Vulnerability,
)
from art_sim.observability.telemetry import Tracer
from art_sim.remediation.approval import HumanApprovalWorkflow, RemediationFlowState
from art_sim.remediation.exporters import (
    GatekeeperExporter,
    JsonRemediationExporter,
    OPARegoExporter,
    OpenTofuRemediationExporter,
    TerraformRemediationExporter,
)
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus, VerificationStatus
from art_sim.remediation.normalization import RemediationPlanner
from art_sim.remediation.state_machine import SimulationLifecycleState
from art_sim.remediation.verification import RemediationVerifier
from art_sim.reporting.markdown import MarkdownReportRenderer
from art_sim.reporting.models import SecuritySimulationReport


@pytest.fixture
def advanced_graph() -> tuple[SimulatedAttackGraph, UUID]:
    """Create the required synthetic container-to-crown-jewel fixture."""
    container_id, node_id, credential_id, role_id, database_id = (uuid4() for _ in range(5))
    graph = SimulatedAttackGraph(
        assets=(
            Asset(
                asset_id=container_id,
                name="shadow-container",
                asset_type=AssetType.KUBERNETES_WORKLOAD,
                environment=Environment.SHADOW,
                provider="aws",
            ),
            Asset(
                asset_id=node_id,
                name="shadow-node",
                asset_type=AssetType.KUBERNETES_NODE,
                environment=Environment.SHADOW,
                provider="aws",
            ),
            Asset(
                asset_id=credential_id,
                name="synthetic-credential",
                asset_type=AssetType.SYNTHETIC_CREDENTIAL,
                environment=Environment.SHADOW,
                provider="synthetic",
            ),
            Asset(
                asset_id=role_id,
                name="shadow-privileged-role",
                asset_type=AssetType.IAM_ROLE,
                environment=Environment.SHADOW,
                criticality=Criticality.HIGH,
                provider="aws",
            ),
            Asset(
                asset_id=database_id,
                name="shadow-crown-jewel",
                asset_type=AssetType.DATABASE,
                environment=Environment.SHADOW,
                criticality=Criticality.CRITICAL,
                is_crown_jewel=True,
                provider="aws",
            ),
        ),
        relationships=(
            AssetRelationship(
                source_asset_id=container_id,
                target_asset_id=node_id,
                relationship_type=RelationshipType.CONTAINER_ESCAPE,
                properties={"modeled": "privileged-workload"},
            ),
            AssetRelationship(
                source_asset_id=node_id,
                target_asset_id=credential_id,
                relationship_type=RelationshipType.CREDENTIAL_ACCESS,
            ),
            AssetRelationship(
                source_asset_id=credential_id,
                target_asset_id=role_id,
                relationship_type=RelationshipType.IAM_ASSUME_ROLE,
                properties={"permissions_gained": "simulated-db-read"},
            ),
            AssetRelationship(
                source_asset_id=role_id,
                target_asset_id=database_id,
                relationship_type=RelationshipType.ACCESS,
            ),
        ),
    )
    return graph, container_id


def test_advanced_relations_support_a_multihop_simulated_path(
    advanced_graph: tuple[SimulatedAttackGraph, UUID],
) -> None:
    """Container escape, credential access, and role assumption form one bounded path."""
    graph, source_id = advanced_graph
    path = graph.find_shortest_path_to_crown_jewel(source_id)

    assert [step.relationship_type for step in path.steps] == [
        RelationshipType.CONTAINER_ESCAPE,
        RelationshipType.CREDENTIAL_ACCESS,
        RelationshipType.IAM_ASSUME_ROLE,
        RelationshipType.ACCESS,
    ]


def test_risk_score_uses_cvss_criticality_crown_and_config(
    advanced_graph: tuple[SimulatedAttackGraph, UUID],
) -> None:
    """Risk is transparent, elevated by evidence, and reduced by a longer-path penalty."""
    graph, source_id = advanced_graph
    path = graph.find_shortest_path_to_crown_jewel(source_id)
    vulnerability = Vulnerability(
        cve_id="CVE-2024-12345",
        title="Synthetic vulnerable container",
        severity=Criticality.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_asset_id=source_id,
        exploit_available=True,
        affected_component="synthetic-runtime",
        fixed_version="9.9.9",
    )
    baseline = RiskScorer(RiskScoringSettings(path_length_penalty=0.0)).assess(
        path, graph.assets, (vulnerability,)
    )
    penalized = RiskScorer(RiskScoringSettings(path_length_penalty=5.0)).assess(
        path, graph.assets, (vulnerability,)
    )

    assert baseline.score > 70.0
    assert baseline.breakdown.cvss > 0.0
    assert baseline.breakdown.crown_jewel > 0.0
    assert penalized.score < baseline.score


def test_breaking_modeled_relation_removes_path_and_reduces_blast_radius(
    advanced_graph: tuple[SimulatedAttackGraph, UUID],
) -> None:
    """Verification uses a graph copy and proves the attack path disappears after removal."""
    graph, source_id = advanced_graph
    path = graph.find_shortest_path_to_crown_jewel(source_id)
    assessment = RiskScorer().assess(path, graph.assets)
    proposal = RemediationPlanner().propose(path, assessment)
    result = RemediationVerifier().verify(graph, source_id, proposal)

    assert result.status is VerificationStatus.VERIFIED
    assert result.remaining_paths == 0
    assert result.blast_radius_after.blast_radius_percentage < result.blast_radius_before.blast_radius_percentage

    with pytest.raises(TopologyNotFoundError):
        graph.without_relationship(graph.relationships[0]).find_shortest_path_to_crown_jewel(source_id)


def test_blast_radius_counts_critical_and_crown_jewel_assets(
    advanced_graph: tuple[SimulatedAttackGraph, UUID],
) -> None:
    """Reachability metrics have concrete, non-invented numerators and denominators."""
    graph, source_id = advanced_graph
    result = BlastRadiusCalculator().calculate(graph, source_id)

    assert result.reachable_assets == 4
    assert result.reachable_critical_assets == 1
    assert result.crown_jewel_exposure_percentage == 100.0


def test_exporters_render_all_requested_review_only_formats(
    advanced_graph: tuple[SimulatedAttackGraph, UUID],
) -> None:
    """Every exporter derives deterministic content from the same normalized candidate."""
    graph, source_id = advanced_graph
    path = graph.find_shortest_path_to_crown_jewel(source_id)
    proposal = RemediationPlanner().propose(path, RiskScorer().assess(path, graph.assets))
    artifacts = tuple(
        exporter.export(proposal)
        for exporter in (
            JsonRemediationExporter(),
            TerraformRemediationExporter(),
            OpenTofuRemediationExporter(),
            OPARegoExporter(),
            GatekeeperExporter(),
        )
    )

    assert len({artifact.export_format for artifact in artifacts}) == 5
    assert all(proposal.remediation_id.hex[:12] in artifact.file_name for artifact in artifacts)


def test_rego_exporter_escapes_untrusted_reason_text(
    advanced_graph: tuple[SimulatedAttackGraph, UUID],
) -> None:
    """A remediation reason remains a Rego string value, never executable policy syntax."""
    graph, source_id = advanced_graph
    path = graph.find_shortest_path_to_crown_jewel(source_id)
    proposal = RemediationPlanner().propose(path, RiskScorer().assess(path, graph.assets))
    artifact = OPARegoExporter().export(
        proposal.model_copy(update={"reason": 'review\" }\nallow if { true'})
    )

    assert '"reason": "review\\\" }\\nallow if { true"' in artifact.content
    assert "\nallow if" not in artifact.content
    assert artifact.content.splitlines()[2].endswith(" if {")


async def test_human_approval_graph_pauses_resumes_and_verifies(
    advanced_graph: tuple[SimulatedAttackGraph, UUID],
) -> None:
    """The checkpointed LangGraph workflow cannot verify until an operator approves it."""
    graph, source_id = advanced_graph
    path = graph.find_shortest_path_to_crown_jewel(source_id)
    assessment = RiskScorer().assess(path, graph.assets)
    proposal = RemediationPlanner().propose(path, assessment)
    run_id = uuid4()
    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=b"a" * 32)
    paused = await workflow.start(
        RemediationFlowState(
            run_id=run_id,
            source_asset_id=source_id,
            simulated_graph=graph,
            remediation=proposal,
            risk_score=assessment.score,
            approval_required=True,
            approval_status=ApprovalStatus.PENDING,
        )
    )
    assert paused["approval_status"] == ApprovalStatus.PENDING

    final = await workflow.decide(
        run_id,
        decision=ApprovalDecision.APPROVED,
        operator="security-architect",
        reason="Validated Shadow-only candidate.",
    )
    assert final["approval_status"] == ApprovalStatus.APPROVED
    verification = final["verification_result"]
    assert getattr(verification, "status", None) is VerificationStatus.VERIFIED
    assert getattr(final["lifecycle"], "state", None) is SimulationLifecycleState.VERIFIED


def test_report_and_telemetry_use_actual_results(advanced_graph: tuple[SimulatedAttackGraph, UUID]) -> None:
    """Markdown derives before/after and operational sections from concrete result objects."""
    graph, source_id = advanced_graph
    path = graph.find_shortest_path_to_crown_jewel(source_id)
    assessment = RiskScorer().assess(path, graph.assets)
    proposal = RemediationPlanner().propose(path, assessment)
    verification = RemediationVerifier().verify(graph, source_id, proposal)
    tracer = Tracer()
    with tracer.span("risk_scoring"):
        pass
    report = SecuritySimulationReport(
        run_id=tracer.run_id,
        total_assets=len(graph.assets),
        total_critical_assets=sum(asset.criticality is Criticality.CRITICAL for asset in graph.assets),
        attack_paths=(path,),
        assessments=(assessment,),
        blast_radius_before=verification.blast_radius_before,
        remediation=proposal,
        verification=verification,
        telemetry=tuple(tracer.agent_events),
        evidence=("GRAPH_RELATION: simulated CONTAINER_ESCAPE edge",),
    )
    markdown = MarkdownReportRenderer().render(report)

    assert "# Security Simulation Report" in markdown
    assert "## Before vs After" in markdown
    assert "simulated" in markdown
