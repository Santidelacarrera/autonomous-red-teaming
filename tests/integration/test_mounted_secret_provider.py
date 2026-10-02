"""Tests for the mounted-directory external secret provider, including path-traversal defense."""

from __future__ import annotations

from pathlib import Path

import pytest

from art_sim.adapters.mounted_secret_provider import MountedSecretsProvider
from art_sim.domain.exceptions import ConfigurationError, DependencyUnavailableError
from art_sim.security.secrets import SecretProviderCapability


@pytest.fixture
def mount(tmp_path: Path) -> Path:
    (tmp_path / "ART_SIM_APPROVAL_SECRET").write_text("super-approval-secret\n", encoding="utf-8")
    (tmp_path / "ART_DATABASE_DSN").write_text("postgresql://u:p@h/db", encoding="utf-8")
    (tmp_path / "EMPTY").write_text("", encoding="utf-8")
    return tmp_path


def test_declares_external_capability(mount: Path) -> None:
    assert MountedSecretsProvider.deployment_capability is SecretProviderCapability.EXTERNAL
    MountedSecretsProvider(mount)


def test_missing_directory_is_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        MountedSecretsProvider(tmp_path / "does-not-exist")


async def test_reads_and_caches_secret(mount: Path) -> None:
    provider = MountedSecretsProvider(mount)
    secret = await provider.get_secret("ART_SIM_APPROVAL_SECRET")
    assert secret.get_secret_value() == "super-approval-secret"
    # Second read is served from cache even if the file changes underneath.
    (mount / "ART_SIM_APPROVAL_SECRET").write_text("rotated", encoding="utf-8")
    assert (await provider.get_secret("ART_SIM_APPROVAL_SECRET")).get_secret_value() == "super-approval-secret"


async def test_reload_refreshes_cache(mount: Path) -> None:
    provider = MountedSecretsProvider(mount)
    await provider.get_secret("ART_SIM_APPROVAL_SECRET")
    (mount / "ART_SIM_APPROVAL_SECRET").write_text("rotated-value", encoding="utf-8")
    await provider.reload(("ART_SIM_APPROVAL_SECRET",))
    assert (await provider.get_secret("ART_SIM_APPROVAL_SECRET")).get_secret_value() == "rotated-value"


async def test_missing_secret_is_configuration_error(mount: Path) -> None:
    provider = MountedSecretsProvider(mount)
    with pytest.raises(ConfigurationError):
        await provider.get_secret("ABSENT_SECRET")


async def test_empty_secret_is_configuration_error(mount: Path) -> None:
    provider = MountedSecretsProvider(mount)
    with pytest.raises(ConfigurationError):
        await provider.get_secret("EMPTY")


@pytest.mark.parametrize(
    "name",
    ["../escape", "..", "a/b", "a\\b", "x", "with space", "../../etc/passwd"],
)
async def test_path_traversal_and_invalid_names_are_rejected(mount: Path, name: str) -> None:
    provider = MountedSecretsProvider(mount)
    with pytest.raises((DependencyUnavailableError, ConfigurationError)):
        await provider.get_secret(name)


async def test_secret_outside_mount_is_unreachable(tmp_path: Path) -> None:
    # A secret file placed OUTSIDE the mount must never be resolvable by name.
    (tmp_path / "outside").write_text("leak", encoding="utf-8")
    mount = tmp_path / "mount"
    mount.mkdir()
    provider = MountedSecretsProvider(mount)
    with pytest.raises((DependencyUnavailableError, ConfigurationError)):
        await provider.get_secret("outside")


async def test_health_check_and_close(mount: Path) -> None:
    provider = MountedSecretsProvider(mount)
    await provider.health_check()
    await provider.get_secret("ART_DATABASE_DSN")
    await provider.close()
