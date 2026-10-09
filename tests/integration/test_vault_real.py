"""``VaultSecretProvider`` against a real HashiCorp Vault server (dev mode, in Docker).

The unit tests use a fake hvac client that raises identically *named* exceptions. This file
drives the genuine ``hvac`` client against a real Vault, so the error classification (not
configured / forbidden / sealed / unreachable) is proven against what Vault and hvac actually
raise, not what a test double was told to raise.

Dev mode is for verification only (in-memory, auto-unsealed, root token ``root``): it says
nothing about production Vault hardening, auth methods or HA. Skipped, visibly, when Docker or
the image is unavailable; override the image with ``ART_VAULT_IMAGE``.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from uuid import uuid4

import pytest

hvac = pytest.importorskip("hvac")

from art_sim.adapters.vault_secret_provider import VaultSecretProvider
from art_sim.domain.exceptions import ConfigurationError, DependencyUnavailableError

IMAGE = os.getenv("ART_VAULT_IMAGE", "hashicorp/vault:1.15")
ROOT_TOKEN = "root"
SECRET_PATH = "art-sim/approval-hmac"
SECRET_VALUE = "v" * 40


def _docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


@pytest.fixture
def vault() -> Iterator[tuple[str, str]]:
    if shutil.which("docker") is None or _docker("info").returncode != 0:
        pytest.skip("Docker daemon is not available")
    if _docker("image", "inspect", IMAGE).returncode != 0 and _docker("pull", IMAGE, timeout=300).returncode != 0:
        pytest.skip(f"cannot pull {IMAGE} (offline or rate-limited; set ART_VAULT_IMAGE)")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    name = f"art-sim-vault-{uuid4().hex[:8]}"
    started = _docker(
        "run", "-d", "--name", name, "--cap-add=IPC_LOCK", "-p", f"127.0.0.1:{port}:8200",
        "-e", f"VAULT_DEV_ROOT_TOKEN_ID={ROOT_TOKEN}", "-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200", IMAGE,
    )
    if started.returncode != 0:
        pytest.skip(f"could not start Vault: {started.stderr.strip()[:200]}")
    url = f"http://127.0.0.1:{port}"
    try:
        client = hvac.Client(url=url, token=ROOT_TOKEN)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                if client.sys.is_initialized() and not client.sys.is_sealed():
                    break
            except Exception:  # noqa: BLE001, S110 - still starting
                pass
            time.sleep(0.5)
        else:
            pytest.skip("Vault did not become ready in time")
        client.secrets.kv.v2.create_or_update_secret(
            path=SECRET_PATH, secret={"value": SECRET_VALUE}, mount_point="secret"
        )
        yield name, url
    finally:
        _docker("rm", "-f", name)


def _provider(url: str, token: str = ROOT_TOKEN, *, max_attempts: int = 4) -> VaultSecretProvider:
    return VaultSecretProvider(hvac.Client(url=url, token=token), max_attempts=max_attempts)


async def test_reads_a_kv2_secret_through_the_real_client(vault: tuple[str, str]) -> None:
    _, url = vault
    provider = _provider(url)
    assert (await provider.get_secret(SECRET_PATH)).get_secret_value() == SECRET_VALUE
    await provider.health_check()
    await provider.close()


async def test_missing_path_is_a_configuration_error_not_an_outage(vault: tuple[str, str]) -> None:
    _, url = vault
    with pytest.raises(ConfigurationError, match="not configured"):
        await _provider(url).get_secret("art-sim/does-not-exist")


async def test_token_without_policy_cannot_read_and_fails_closed(vault: tuple[str, str]) -> None:
    _, url = vault
    root = hvac.Client(url=url, token=ROOT_TOKEN)
    limited = root.auth.token.create(policies=["default"], ttl="5m")["auth"]["client_token"]
    with pytest.raises(ConfigurationError):
        await _provider(url, token=limited).get_secret(SECRET_PATH)


async def test_bogus_token_fails_closed(vault: tuple[str, str]) -> None:
    _, url = vault
    with pytest.raises(ConfigurationError):
        await _provider(url, token="s.not-a-real-token").get_secret(SECRET_PATH)


async def test_reload_picks_up_a_rotated_secret(vault: tuple[str, str]) -> None:
    _, url = vault
    provider = _provider(url)
    assert (await provider.get_secret(SECRET_PATH)).get_secret_value() == SECRET_VALUE
    hvac.Client(url=url, token=ROOT_TOKEN).secrets.kv.v2.create_or_update_secret(
        path=SECRET_PATH, secret={"value": "r" * 40}, mount_point="secret"
    )
    assert (await provider.get_secret(SECRET_PATH)).get_secret_value() == SECRET_VALUE  # cached
    await provider.reload((SECRET_PATH,))
    assert (await provider.get_secret(SECRET_PATH)).get_secret_value() == "r" * 40


async def test_a_sealed_vault_makes_readiness_fail(vault: tuple[str, str]) -> None:
    _, url = vault
    provider = _provider(url)
    await provider.health_check()
    # Dev mode auto-unseals and exposes no unseal keys; sealing it is the supported way to
    # prove the readiness signal. (A real cluster would be sealed by an operator.)
    hvac.Client(url=url, token=ROOT_TOKEN).sys.seal()
    with pytest.raises(DependencyUnavailableError):
        await provider.health_check()


async def test_unreachable_vault_is_reported_as_unavailable_after_bounded_retries(
    vault: tuple[str, str],
) -> None:
    name, url = vault
    provider = _provider(url, max_attempts=2)
    assert _docker("stop", "-t", "1", name).returncode == 0
    with pytest.raises(DependencyUnavailableError):
        await provider.get_secret(SECRET_PATH)
    with pytest.raises(DependencyUnavailableError):
        await provider.health_check()
