"""Tests for the AWS Secrets Manager adapter using a fake boto3-shaped client.

No network access or the ``boto3``/``moto`` dependency is required for these tests: the
adapter's constructor accepts any object exposing the boto3 ``secretsmanager`` client
surface it actually calls (``get_secret_value``, ``list_secrets``, ``close``), so a minimal
fake reproduces botocore's synchronous, exception-raising behavior precisely enough to
exercise caching, error mapping and retry logic. ``from_region`` (which imports ``boto3``)
is covered separately and skipped when the dependency is absent.
"""

from __future__ import annotations

from typing import Any

import pytest

from art_sim.adapters.aws_secrets_manager_provider import AwsSecretsManagerProvider
from art_sim.domain.exceptions import ConfigurationError, DependencyUnavailableError
from art_sim.security.secrets import SecretProviderCapability


class _ClientError(Exception):
    """Mimics ``botocore.exceptions.ClientError``'s ``.response`` contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeSecretsManagerClient:
    """Minimal synchronous stand-in for a boto3 ``secretsmanager`` client."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.calls: list[str] = []
        self.closed = False
        self.transient_failures_remaining = 0

    def get_secret_value(self, SecretId: str) -> dict[str, Any]:
        self.calls.append(SecretId)
        if self.transient_failures_remaining > 0:
            self.transient_failures_remaining -= 1
            raise _ClientError("ThrottlingException")
        if SecretId not in self.values:
            raise _ClientError("ResourceNotFoundException")
        return {"SecretString": self.values[SecretId]}

    def list_secrets(self, MaxResults: int = 1) -> dict[str, Any]:
        return {"SecretList": []}

    def close(self) -> None:
        self.closed = True


def test_declares_external_capability() -> None:
    assert AwsSecretsManagerProvider.deployment_capability is SecretProviderCapability.EXTERNAL


async def test_reads_and_caches_secret() -> None:
    client = FakeSecretsManagerClient()
    client.values["ART_SIM_APPROVAL_SECRET"] = "super-approval-secret"
    provider = AwsSecretsManagerProvider(client)
    secret = await provider.get_secret("ART_SIM_APPROVAL_SECRET")
    assert secret.get_secret_value() == "super-approval-secret"
    client.values["ART_SIM_APPROVAL_SECRET"] = "rotated"
    # Cached: second call does not hit the client again.
    assert (await provider.get_secret("ART_SIM_APPROVAL_SECRET")).get_secret_value() == (
        "super-approval-secret"
    )
    assert client.calls == ["ART_SIM_APPROVAL_SECRET"]


async def test_missing_secret_is_configuration_error() -> None:
    provider = AwsSecretsManagerProvider(FakeSecretsManagerClient())
    with pytest.raises(ConfigurationError):
        await provider.get_secret("ABSENT_SECRET")


async def test_empty_secret_string_is_configuration_error() -> None:
    client = FakeSecretsManagerClient()
    client.values["EMPTY"] = ""
    provider = AwsSecretsManagerProvider(client)
    with pytest.raises(ConfigurationError):
        await provider.get_secret("EMPTY")


async def test_transient_throttling_is_retried_then_succeeds() -> None:
    client = FakeSecretsManagerClient()
    client.values["ART_DATABASE_DSN"] = "postgresql://u:p@h/db"
    client.transient_failures_remaining = 2
    provider = AwsSecretsManagerProvider(client, max_attempts=4)
    secret = await provider.get_secret("ART_DATABASE_DSN")
    assert secret.get_secret_value() == "postgresql://u:p@h/db"


async def test_persistent_throttling_fails_as_dependency_unavailable() -> None:
    client = FakeSecretsManagerClient()
    client.values["X"] = "value"
    client.transient_failures_remaining = 99
    provider = AwsSecretsManagerProvider(client, max_attempts=2)
    with pytest.raises(DependencyUnavailableError):
        await provider.get_secret("X")


async def test_reload_refreshes_cache() -> None:
    client = FakeSecretsManagerClient()
    client.values["ART_SIM_APPROVAL_SECRET"] = "original"
    provider = AwsSecretsManagerProvider(client)
    await provider.get_secret("ART_SIM_APPROVAL_SECRET")
    client.values["ART_SIM_APPROVAL_SECRET"] = "rotated-value"
    await provider.reload(("ART_SIM_APPROVAL_SECRET",))
    assert (await provider.get_secret("ART_SIM_APPROVAL_SECRET")).get_secret_value() == (
        "rotated-value"
    )


async def test_health_check_and_close() -> None:
    client = FakeSecretsManagerClient()
    provider = AwsSecretsManagerProvider(client)
    await provider.health_check()
    await provider.close()
    assert client.closed is True


async def test_health_check_failure_is_dependency_unavailable() -> None:
    class FailingClient(FakeSecretsManagerClient):
        def list_secrets(self, MaxResults: int = 1) -> dict[str, Any]:
            raise RuntimeError("network down")

    provider = AwsSecretsManagerProvider(FailingClient())
    with pytest.raises(DependencyUnavailableError):
        await provider.health_check()


def test_from_region_without_boto3_raises_configuration_error() -> None:
    try:
        import boto3  # noqa: F401
    except ImportError:
        with pytest.raises(ConfigurationError):
            AwsSecretsManagerProvider.from_region("us-east-1")
    else:
        pytest.skip("boto3 is installed; from_region constructs a real client instead")
