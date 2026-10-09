"""Mounted-directory external secret provider — a real, deployment-owned production adapter.

Resolves named secrets from a mounted secrets directory (one file per secret, the pattern
used by Docker secrets at ``/run/secrets`` and Kubernetes projected secret volumes). It
satisfies ``ExternalSecretProvider`` (declares the EXTERNAL trust boundary) without coupling
the codebase to any cloud SDK. Values are cached; ``reload`` atomically refreshes them.

Security: secret names are strictly validated and the resolved file path is confined to the
base directory, so a crafted name (``../../etc/passwd``) can never escape the mount.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import ClassVar

from pydantic import SecretStr

from art_sim.domain.exceptions import ConfigurationError, DependencyUnavailableError
from art_sim.security.secrets import SecretProviderCapability

_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,256}$")


class MountedSecretsProvider:
    """Read secrets from files in a mounted directory, one file per secret name."""

    deployment_capability: ClassVar[SecretProviderCapability] = SecretProviderCapability.EXTERNAL

    def __init__(self, base_dir: Path) -> None:
        """Bind the provider to a mounted secrets directory that must already exist."""
        self._base = base_dir.resolve()
        if not self._base.is_dir():
            raise ConfigurationError(f"Secrets directory {base_dir!s} does not exist")
        self._cache: dict[str, SecretStr] = {}
        self._lock = asyncio.Lock()

    def _resolve(self, name: str) -> Path:
        # Reject path separators and traversal outright, then confirm containment.
        if not _NAME.match(name) or "/" in name or "\\" in name or ".." in name:
            raise DependencyUnavailableError("Requested secret name is invalid")
        candidate = (self._base / name).resolve()
        if candidate.parent != self._base:
            raise DependencyUnavailableError("Requested secret name is invalid")
        return candidate

    async def get_secret(self, name: str) -> SecretStr:
        """Return a cached secret, loading it from the mount on first access."""
        async with self._lock:
            if name in self._cache:
                return self._cache[name]
            value = await self._read(name)
            self._cache[name] = value
            return value

    async def _read(self, name: str) -> SecretStr:
        path = self._resolve(name)
        try:
            raw = await asyncio.to_thread(path.read_text, "utf-8")
        except FileNotFoundError as error:
            raise ConfigurationError(f"Required secret {name!r} is not configured") from error
        except OSError as error:
            raise DependencyUnavailableError("Secret storage is unavailable") from error
        value = raw.rstrip("\n")
        if not value:
            raise ConfigurationError(f"Required secret {name!r} is empty")
        return SecretStr(value)

    async def reload(self, names: tuple[str, ...]) -> None:
        """Atomically refresh selected cached values or retain the last valid set."""
        async with self._lock:
            refreshed = {name: await self._read(name) for name in names}
            self._cache.update(refreshed)

    async def health_check(self) -> None:
        """Verify the mount is present and readable without exposing any value."""
        try:
            await asyncio.to_thread(lambda: list(self._base.iterdir()))
        except OSError as error:
            raise DependencyUnavailableError("Secret storage is unavailable") from error

    async def close(self) -> None:
        """Drop cached secret material from memory."""
        async with self._lock:
            self._cache.clear()
