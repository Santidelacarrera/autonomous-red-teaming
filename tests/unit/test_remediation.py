"""Phase 3 tests for safe patch generation and idempotent GitHub publication."""

from __future__ import annotations

from collections.abc import Mapping
from uuid import uuid4

import pytest

from art_sim.agents.models import (
    AttackPlan,
    AttackPlanStep,
    MitreTechnique,
    PlanStatus,
    SimulationAction,
    SimulationResult,
    SimulationStatus,
)
from art_sim.domain.exceptions import RemediationEligibilityError
from art_sim.domain.models import AssetType, Environment, RelationshipType
from art_sim.infrastructure.github_pr_service import (
    GitHubApiClient,
    GitHubPRService,
    GitHubSettings,
)
from art_sim.remediation.agent import RemediationAgent
from art_sim.remediation.generator import PolicyRemediationGenerator
from art_sim.remediation.models import RemediationRequest
from art_sim.security.sanitizer import SafeAssetReference


class FakeGitHubApiClient(GitHubApiClient):
    """Deterministic GitHub fake for service tests without network access."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, object] | None = None,
        params: Mapping[str, str] | None = None,
        allow_not_found: bool = False,
    ) -> object | None:
        """Return the narrow payload expected at each GitHub REST operation."""
        del json_body, params, allow_not_found
        self.calls.append((method, path))
        if method == "GET" and "/git/ref/heads/ctem%2F" in path:
            return None
        if method == "GET" and "/git/ref/heads/main" in path:
            return {"object": {"sha": "base-sha"}}
        if method == "GET" and "/contents/" in path:
            return None
        if method == "GET" and path.endswith("/pulls"):
            return []
        if method == "POST" and path.endswith("/pulls"):
            return {"number": 42, "html_url": "https://github.example/acme/red-team/pull/42"}
        return {"ok": True}


@pytest.fixture
def remediation_request() -> RemediationRequest:
    """Create an approved Shadow simulation request without untrusted text fields."""
    source_id, target_id = uuid4(), uuid4()
    plan = AttackPlan(
        source_asset_id=source_id,
        target_asset_id=target_id,
        environment=Environment.SHADOW,
        scoped_asset_ids=(source_id, target_id),
        steps=(
            AttackPlanStep(
                source_asset_id=source_id,
                target_asset_id=target_id,
                relationship_type=RelationshipType.NETWORK_REACHABLE,
                technique=MitreTechnique(
                    technique_id="T1046", tactic="discovery", name="Network Service Discovery"
                ),
                action=SimulationAction.OBSERVE_TOPOLOGY,
            ),
        ),
        status=PlanStatus.APPROVED,
    )
    return RemediationRequest(
        plan=plan,
        simulation=SimulationResult(
            status=SimulationStatus.SUCCEEDED,
            executed_actions=(SimulationAction.OBSERVE_TOPOLOGY,),
            evidence=("ignored by remediation prompt",),
        ),
        target=SafeAssetReference(
            asset_id=target_id,
            asset_type=AssetType.KUBERNETES_WORKLOAD,
            environment="shadow",
            is_crown_jewel=False,
        ),
    )


async def test_remediation_agent_generates_opt_in_network_policy(
    remediation_request: RemediationRequest,
) -> None:
    """A successful network simulation produces a Shadow-only review candidate."""
    artifact = await RemediationAgent(PolicyRemediationGenerator()).generate(remediation_request)

    assert artifact.file_path.startswith("kubernetes/network-policies/")
    assert "namespace: shadow" in artifact.content
    assert "egress-remediation" in artifact.content
    assert len(artifact.idempotency_key) == 64


async def test_remediation_agent_rejects_unapproved_plan(remediation_request: RemediationRequest) -> None:
    """Remediation cannot bypass the supervisor approval gate."""
    invalid_request = remediation_request.model_copy(
        update={"plan": remediation_request.plan.model_copy(update={"status": PlanStatus.DRAFT})}
    )
    with pytest.raises(RemediationEligibilityError, match="approved"):
        await RemediationAgent(PolicyRemediationGenerator()).generate(invalid_request)


async def test_remediation_agent_generates_unattached_iam_candidate(
    remediation_request: RemediationRequest,
) -> None:
    """A role-assumption simulation selects the IAM policy template without attaching it."""
    role_step = remediation_request.plan.steps[0].model_copy(
        update={"action": SimulationAction.SIMULATE_ROLE_ASSUMPTION}
    )
    role_request = remediation_request.model_copy(
        update={
            "plan": remediation_request.plan.model_copy(update={"steps": (role_step,)}),
            "target": remediation_request.target.model_copy(update={"asset_type": AssetType.IAM_ROLE}),
        }
    )

    artifact = await RemediationAgent(PolicyRemediationGenerator()).generate(role_request)

    assert artifact.file_path.startswith("aws/iam-policies/")
    assert '"Action": "sts:AssumeRole"' in artifact.content


async def test_github_service_creates_branch_commit_and_pull_request(
    remediation_request: RemediationRequest,
) -> None:
    """The publisher performs the expected idempotent GitHub REST sequence."""
    artifact = await RemediationAgent(PolicyRemediationGenerator()).generate(remediation_request)
    client = FakeGitHubApiClient()
    service = GitHubPRService(
        GitHubSettings(owner="acme", repository="red-team", token="test-token"), client
    )

    receipt = await service.publish(artifact, remediation_request)

    assert receipt.number == 42
    assert receipt.created_commit is True
    assert [method for method, _ in client.calls] == ["GET", "GET", "POST", "GET", "PUT", "GET", "POST"]
