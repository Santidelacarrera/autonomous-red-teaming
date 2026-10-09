"""Tests for the HashiCorp Vault adapter using a fake hvac-shaped client.

No network access or the ``hvac`` dependency is required: the adapter's constructor takes
any object exposing the small ``hvac.Client`` surface it actually calls
(``secrets.kv.v2.read_secret_version``, ``sys.is_sealed``), and exception classification is
done by exception *class name* (matching hvac's own ``InvalidPath``/``Forbidden``/
``Unauthorized``), so a fake raising identically named exceptions exercises the same paths.
"""

from __future__ import annotations

from typing import Any

import pytest

from art_sim.adapters.vault_secret_provider import VaultSecretProvider
from art_sim.domain.exceptions import ConfigurationError, DependencyUnavailableError
from art_sim.security.secrets import SecretProviderCapability


class InvalidPath(Exception):
    """Named to match ``hvac.exceptions.InvalidPath`` for class-name-based classification."""


class VaultDown(Exception):
    """An hvac exception class name that is NOT in the not-configured set (retried)."""


class _KvV2:
    def __init__(self, store: dict[str, dict[str, str]]) -> None:
        self._store = store
        self.calls: list[str] = []
        self.transient_failures_remaining = 0

    def read_secret_version(
        self, path: str, mount_point: str, raise_on_deleted_version: bool = True
    ) -> dict[str, Any]:
        self.calls.append(path)
        if self.transient_failures_remaining > 0:
            self.transient_failures_remaining -= 1
            raise VaultDown("vault is sealed or unreachable")
        if path not in self._store:
            raise InvalidPath(f"no secret at {path}")
        return {"data": {"data": self._store[path]}}


class _Secrets:
    def __init__(self, kv_v2: _KvV2) -> None:
        self.kv = type("Kv", (), {"v2": kv_v2})()


class _Sys:
    def __init__(self, sealed: bool = False) -> None:
        self.sealed = sealed

    def is_sealed(self) -> bool:
        return self.sealed


class FakeVaultClient:
    """Minimal synchronous stand-in for ``hvac.Client``."""

    def __init__(self, sealed: bool = False) -> None:
        self.store: dict[str, dict[str, str]] = {}
        self.kv_v2 = _KvV2(self.store)
        self.secrets = _Secrets(self.kv_v2)
        self.sys = _Sys(sealed)
        self.session = type("Session", (), {"close": lambda self: None})()


def test_declares_external_capability() -> None:
    assert VaultSecretProvider.deployment_capability is SecretProviderCapability.EXTERNAL


async def test_reads_and_caches_secret() -> None:
    client = FakeVaultClient()
    client.store["ART_SIM_APPROVAL_SECRET"] = {"value": "super-approval-secret"}
    provider = VaultSecretProvider(client)
    secret = await provider.get_secret("ART_SIM_APPROVAL_SECRET")
    assert secret.get_secret_value() == "super-approval-secret"
    client.store["ART_SIM_APPROVAL_SECRET"] = {"value": "rotated"}
    assert (await provider.get_secret("ART_SIM_APPROVAL_SECRET")).get_secret_value() == (
        "super-approval-secret"
    )
    assert client.kv_v2.calls == ["ART_SIM_APPROVAL_SECRET"]


async def test_custom_field_name() -> None:
    client = FakeVaultClient()
    client.store["ART_DATABASE_DSN"] = {"dsn": "postgresql://u:p@h/db"}
    provider = VaultSecretProvider(client, field="dsn")
    secret = await provider.get_secret("ART_DATABASE_DSN")
    assert secret.get_secret_value() == "postgresql://u:p@h/db"


async def test_missing_path_is_configuration_error() -> None:
    provider = VaultSecretProvider(FakeVaultClient())
    with pytest.raises(ConfigurationError):
        await provider.get_secret("ABSENT")


async def test_missing_field_is_configuration_error() -> None:
    client = FakeVaultClient()
    client.store["X"] = {"other_field": "value"}
    provider = VaultSecretProvider(client)
    with pytest.raises(ConfigurationError):
        await provider.get_secret("X")


async def test_transient_failure_is_retried_then_succeeds() -> None:
    client = FakeVaultClient()
    client.store["X"] = {"value": "ok"}
    client.kv_v2.transient_failures_remaining = 2
    provider = VaultSecretProvider(client, max_attempts=4)
    secret = await provider.get_secret("X")
    assert secret.get_secret_value() == "ok"


async def test_persistent_failure_is_dependency_unavailable() -> None:
    client = FakeVaultClient()
    client.store["X"] = {"value": "ok"}
    client.kv_v2.transient_failures_remaining = 99
    provider = VaultSecretProvider(client, max_attempts=2)
    with pytest.raises(DependencyUnavailableError):
        await provider.get_secret("X")


async def test_reload_refreshes_cache() -> None:
    client = FakeVaultClient()
    client.store["ART_SIM_APPROVAL_SECRET"] = {"value": "original"}
    provider = VaultSecretProvider(client)
    await provider.get_secret("ART_SIM_APPROVAL_SECRET")
    client.store["ART_SIM_APPROVAL_SECRET"] = {"value": "rotated-value"}
    await provider.reload(("ART_SIM_APPROVAL_SECRET",))
    assert (await provider.get_secret("ART_SIM_APPROVAL_SECRET")).get_secret_value() == (
        "rotated-value"
    )


async def test_health_check_rejects_sealed_vault() -> None:
    provider = VaultSecretProvider(FakeVaultClient(sealed=True))
    with pytest.raises(DependencyUnavailableError):
        await provider.health_check()


async def test_health_check_and_close() -> None:
    provider = VaultSecretProvider(FakeVaultClient(sealed=False))
    await provider.health_check()
    await provider.close()


def test_from_url_without_hvac_raises_configuration_error() -> None:
    try:
        import hvac  # noqa: F401
    except ImportError:
        with pytest.raises(ConfigurationError):
            VaultSecretProvider.from_url("https://vault.example.invalid", "token")
    else:
        pytest.skip("hvac is installed; from_url constructs a real client instead")
