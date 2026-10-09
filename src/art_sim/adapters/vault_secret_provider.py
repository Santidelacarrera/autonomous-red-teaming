"""HashiCorp Vault external secret provider — a real, deployment-owned production adapter.

Resolves named secrets from a Vault KV v2 mount via ``hvac``, satisfying
``ExternalSecretProvider`` (declares the EXTERNAL trust boundary). This module is not
imported by core code; the composition root constructs it only when
``ART_SECRET_PROVIDER=hashicorp_vault``.

Design:

- each ``name`` passed to ``get_secret`` is treated as a KV v2 secret *path* under the
  configured mount (``<mount>/data/<name>``) and the configured ``field`` is read from it,
  so one Vault secret can be a single value (default field ``value``) or a wider document;
- the token is supplied by the deployment (AppRole, Kubernetes auth, or an already-issued
  client token) and is never read, logged or renewed by this module beyond what ``hvac``
  itself does — token lifecycle (renewal, AppRole login) is the caller's responsibility;
- a 403/permission-denied or 404/invalid-path response fails closed as a configuration
  error; connection failures and 5xx responses are retried with bounded jittered backoff and
  then reported as a dependency-unavailable error;
- values are cached in-process; ``reload`` atomically refreshes selected entries.

``hvac`` is an opt-in extra (``pip install .[vault]``). Core code never imports it.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from pydantic import SecretStr
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from art_sim.domain.exceptions import ConfigurationError, DependencyUnavailableError
from art_sim.security.secrets import SecretProviderCapability


class VaultUnavailableError(Exception):
    """Internal marker raised by ``_fetch`` for transient Vault failures worth retrying."""


class VaultSecretProvider:
    """Resolve secrets from a HashiCorp Vault KV v2 mount through a caller-supplied client."""

    deployment_capability: ClassVar[SecretProviderCapability] = SecretProviderCapability.EXTERNAL

    def __init__(
        self,
        client: Any,
        *,
        mount_point: str = "secret",
        field: str = "value",
        max_attempts: int = 4,
    ) -> None:
        """Bind the provider to an already-authenticated ``hvac.Client``.

        The caller owns Vault addressing, TLS, and token acquisition/renewal; this adapter
        never constructs a Vault client or performs an auth-method login.
        """
        self._client = client
        self._mount_point = mount_point
        self._field = field
        self._max_attempts = max_attempts
        self._cache: dict[str, SecretStr] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def from_url(
        cls,
        url: str,
        token: str,
        *,
        mount_point: str = "secret",
        field: str = "value",
    ) -> VaultSecretProvider:
        """Build a provider over a new ``hvac.Client`` for the given Vault address.

        Raises:
            ConfigurationError: If ``hvac`` is not installed (missing ``.[vault]`` extra).
        """
        try:
            import hvac
        except ImportError as error:  # pragma: no cover - exercised via extras-absent CI lane
            raise ConfigurationError(
                "hvac is required for VaultSecretProvider; install the 'vault' extra"
            ) from error
        client = hvac.Client(url=url, token=token)
        return cls(client, mount_point=mount_point, field=field)

    async def get_secret(self, name: str) -> SecretStr:
        """Return a cached secret, fetching it from Vault KV v2 on first access."""
        async with self._lock:
            if name in self._cache:
                return self._cache[name]
            value = await self._fetch(name)
            self._cache[name] = value
            return value

    async def _fetch(self, name: str) -> SecretStr:
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self._max_attempts),
                wait=wait_exponential_jitter(initial=0.2, max=5.0),
                retry=retry_if_exception_type(VaultUnavailableError),
                reraise=True,
            ):
                with attempt:
                    response = await asyncio.to_thread(self._read_secret_version, name)
        except VaultUnavailableError as error:
            raise DependencyUnavailableError("HashiCorp Vault is unavailable") from error
        data = response.get("data", {}).get("data", {}) if isinstance(response, dict) else {}
        value = data.get(self._field)
        if not isinstance(value, str) or not value:
            raise ConfigurationError(f"Required secret {name!r} has no usable {self._field!r} field")
        return SecretStr(value)

    # hvac raises distinct exception classes per HTTP status rather than a status-coded
    # single type; matching by class name avoids importing hvac just to classify errors,
    # so this also works against a test double that raises identically named exceptions.
    _NOT_CONFIGURED_ERROR_NAMES: ClassVar[frozenset[str]] = frozenset(
        {"InvalidPath", "Forbidden", "Unauthorized"}
    )

    def _read_secret_version(self, name: str) -> dict[str, Any]:
        """Run synchronously in a worker thread; classifies the raised exception type."""
        try:
            result: dict[str, Any] = self._client.secrets.kv.v2.read_secret_version(
                path=name, mount_point=self._mount_point, raise_on_deleted_version=True
            )
            return result
        except Exception as error:
            if type(error).__name__ in self._NOT_CONFIGURED_ERROR_NAMES:
                raise ConfigurationError(f"Required secret {name!r} is not configured") from error
            raise VaultUnavailableError(str(error)) from error

    async def reload(self, names: tuple[str, ...]) -> None:
        """Atomically refresh selected cached values or retain the last valid set."""
        async with self._lock:
            refreshed = {name: await self._fetch(name) for name in names}
            self._cache.update(refreshed)

    async def health_check(self) -> None:
        """Verify Vault connectivity and seal status without reading or logging any value."""
        try:
            is_sealed = await asyncio.to_thread(lambda: self._client.sys.is_sealed())
        except Exception as error:
            raise DependencyUnavailableError("HashiCorp Vault is unavailable") from error
        if is_sealed:
            raise DependencyUnavailableError("HashiCorp Vault is sealed")

    async def close(self) -> None:
        """Drop cached secret material from memory and release the underlying session."""
        async with self._lock:
            self._cache.clear()
        session = getattr(self._client, "session", None)
        close = getattr(session, "close", None)
        if callable(close):
            await asyncio.to_thread(close)
