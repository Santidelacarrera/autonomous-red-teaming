"""AWS Secrets Manager adapter against ``moto``'s emulation of the real service API.

The unit tests use a hand-written boto3-shaped fake; this file drives the adapter through the
genuine boto3 client, botocore request signing/serialization and the service's actual error
shapes (``ResourceNotFoundException``, binary secrets, versions), emulated in-process by moto.
It also proves the key use case end to end: the approval HMAC key is resolved from the secret
manager and signs/verifies an approval, and rotating the secret invalidates old signatures.
This is *not* a connection to a live AWS account; see docs/integrations.md.
"""

from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from art_sim.adapters.aws_secrets_manager_provider import AwsSecretsManagerProvider
from art_sim.domain.exceptions import ApprovalRequiredError, ConfigurationError
from art_sim.platform.config import OperationalSettings, RuntimeEnvironment
from art_sim.remediation.approval import HumanApprovalWorkflow, RemediationFlowState
from art_sim.remediation.models import ApprovalDecision, ApprovalStatus
from art_sim.remediation.verification import RemediationVerifier
from art_sim.security.secrets import SecretProviderCapability

HMAC_NAME = "art-sim/approval-hmac"
KEY_V1 = "k" * 40
KEY_V2 = "z" * 40


@pytest.fixture
def secrets_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    for name, value in (
        ("AWS_ACCESS_KEY_ID", "testing"),
        ("AWS_SECRET_ACCESS_KEY", "testing"),
        ("AWS_DEFAULT_REGION", "eu-west-1"),
    ):
        monkeypatch.setenv(name, value)
    with moto.mock_aws():
        yield boto3.client("secretsmanager", region_name="eu-west-1")


async def test_real_boto3_client_resolves_a_secret(secrets_client: object) -> None:
    secrets_client.create_secret(Name=HMAC_NAME, SecretString=KEY_V1)  # type: ignore[attr-defined]
    provider = AwsSecretsManagerProvider(secrets_client)
    assert AwsSecretsManagerProvider.deployment_capability is SecretProviderCapability.EXTERNAL
    assert (await provider.get_secret(HMAC_NAME)).get_secret_value() == KEY_V1
    assert KEY_V1 not in repr(await provider.get_secret(HMAC_NAME))  # SecretStr never prints


async def test_missing_secret_fails_closed_with_a_safe_error(secrets_client: object) -> None:
    """A secret that is not configured is a startup/configuration failure, never an empty key."""
    provider = AwsSecretsManagerProvider(secrets_client)
    with pytest.raises(ConfigurationError, match="not configured"):
        await provider.get_secret("does/not/exist")


async def test_approval_signing_key_comes_from_the_secret_manager(secrets_client: object) -> None:
    secrets_client.create_secret(Name=HMAC_NAME, SecretString=KEY_V1)  # type: ignore[attr-defined]
    settings = OperationalSettings(
        environment=RuntimeEnvironment.PRODUCTION, approval_secret_name="ART_SIM_APPROVAL_SECRET"
    ).model_copy(update={"approval_secret_name": HMAC_NAME})
    key = await settings.approval_secret_async(AwsSecretsManagerProvider(secrets_client))
    assert key == KEY_V1.encode()

    workflow = HumanApprovalWorkflow(RemediationVerifier(), approval_secret=key)
    run_id = uuid4()
    from art_sim.worker.fixtures import shadow_demo_scenario

    scenario = shadow_demo_scenario()
    from art_sim.attack.risk import RiskScorer
    from art_sim.remediation.normalization import RemediationPlanner

    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assessment = RiskScorer().assess(path, scenario.graph.assets)
    await workflow.start(
        RemediationFlowState(
            run_id=run_id,
            source_asset_id=scenario.source_asset_id,
            simulated_graph=scenario.graph,
            remediation=RemediationPlanner().propose(path, assessment),
            risk_score=assessment.score,
            approval_required=True,
            approval_status=ApprovalStatus.PENDING,
        )
    )
    final = await workflow.decide(
        run_id, decision=ApprovalDecision.APPROVED, operator="alice", reason="Reviewed evidence."
    )
    assert final["approval_status"] is ApprovalStatus.APPROVED


async def test_rotating_the_secret_invalidates_proofs_signed_with_the_old_key(
    secrets_client: object,
) -> None:
    from langgraph.checkpoint.memory import MemorySaver

    from art_sim.attack.risk import RiskScorer
    from art_sim.remediation.normalization import RemediationPlanner
    from art_sim.worker.fixtures import shadow_demo_scenario

    secrets_client.create_secret(Name=HMAC_NAME, SecretString=KEY_V1)  # type: ignore[attr-defined]
    settings = OperationalSettings(environment=RuntimeEnvironment.PRODUCTION).model_copy(
        update={"approval_secret_name": HMAC_NAME}
    )
    saver = MemorySaver()
    old_key = await settings.approval_secret_async(AwsSecretsManagerProvider(secrets_client))
    signer = HumanApprovalWorkflow(RemediationVerifier(), checkpointer=saver, approval_secret=old_key)
    scenario = shadow_demo_scenario()
    path = scenario.graph.find_shortest_path_to_crown_jewel(scenario.source_asset_id)
    assessment = RiskScorer().assess(path, scenario.graph.assets)
    run_id = uuid4()
    await signer.start(
        RemediationFlowState(
            run_id=run_id,
            source_asset_id=scenario.source_asset_id,
            simulated_graph=scenario.graph,
            remediation=RemediationPlanner().propose(path, assessment),
            risk_score=assessment.score,
            approval_required=True,
            approval_status=ApprovalStatus.PENDING,
        )
    )
    await signer.decide(run_id, decision=ApprovalDecision.APPROVED, operator="alice", reason="Reviewed evidence.")

    secrets_client.put_secret_value(SecretId=HMAC_NAME, SecretString=KEY_V2)  # type: ignore[attr-defined]
    rotated = await settings.approval_secret_async(AwsSecretsManagerProvider(secrets_client))
    assert rotated == KEY_V2.encode() != old_key
    verifier = HumanApprovalWorkflow(RemediationVerifier(), checkpointer=saver, approval_secret=rotated)
    with pytest.raises(ApprovalRequiredError):  # the old signature no longer verifies
        await verifier.resume_recorded_decision(
            run_id, decision=ApprovalDecision.APPROVED, operator="alice", reason="Reviewed evidence."
        )


async def test_a_short_secret_is_refused_before_it_can_sign(secrets_client: object) -> None:
    secrets_client.create_secret(Name=HMAC_NAME, SecretString="too-short")  # type: ignore[attr-defined]
    settings = OperationalSettings(environment=RuntimeEnvironment.PRODUCTION).model_copy(
        update={"approval_secret_name": HMAC_NAME}
    )
    with pytest.raises(ConfigurationError):
        await settings.approval_secret_async(AwsSecretsManagerProvider(secrets_client))
