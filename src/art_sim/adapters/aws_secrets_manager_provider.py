"""AWS Secrets Manager external secret provider — a real, deployment-owned production adapter.

Resolves named secrets from AWS Secrets Manager via ``boto3``, satisfying
``ExternalSecretProvider`` (declares the EXTERNAL trust boundary). This module is not
imported by core code; the composition root constructs it only when
``ART_SECRET_PROVIDER=aws_secrets_manager``.

Design:

- each ``name`` passed to ``get_secret`` is the Secrets Manager secret *name or ARN*, taken
  verbatim from ``SecretManagerSettings`` (``approval_hmac_secret_name``,
  ``database_secret_name``, ``broker_secret_name``, ...) — never constructed from untrusted
  input;
- values are cached in-process; ``reload`` atomically refreshes selected entries or raises
  without mutating the cache, so a transient AWS failure cannot silently blank a secret that
  is still in use;
- retries are bounded and jittered (``tenacity``) and only cover throttling/transient AWS
  errors, never ``ResourceNotFoundException`` or access-denied, which fail closed immediately;
- secret values are never logged; botocore's own logger is left untouched by this module, so
  deployments must keep botocore logging at its default (non-debug) level in production.

``boto3`` is an opt-in extra (``pip install .[aws]``). Core code never imports it.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from pydantic import SecretStr
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)

from art_sim.domain.exceptions import ConfigurationError, DependencyUnavailableError
from art_sim.security.secrets import SecretProviderCapability

_TRANSIENT_ERROR_CODES = frozenset(
    {
        "ThrottlingException",
        "InternalServiceError",
        "ServiceUnavailable",
        "RequestLimitExceeded",
    }
)


def _is_transient(error: BaseException) -> bool:
    """Retry only throttling/transient AWS failures; everything else fails closed."""
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return False
    code = response.get("Error", {}).get("Code")
    return code in _TRANSIENT_ERROR_CODES


class AwsSecretsManagerProvider:
    """Resolve secrets from AWS Secrets Manager through a caller-supplied boto3 client."""

    deployment_capability: ClassVar[SecretProviderCapability] = SecretProviderCapability.EXTERNAL

    def __init__(
        self,
        client: Any,
        *,
        max_attempts: int = 4,
    ) -> None:
        """Bind the provider to an already-configured ``boto3`` ``secretsmanager`` client.

        The caller owns the client's region, endpoint and credential chain (IAM role,
        environment, or explicit keys); this adapter never constructs AWS credentials.
        """
        self._client = client
        self._max_attempts = max_attempts
        self._cache: dict[str, SecretStr] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def from_region(cls, region_name: str, *, endpoint_url: str | None = None) -> AwsSecretsManagerProvider:
        """Build a provider over a new ``boto3`` client for the given region.

        Raises:
            ConfigurationError: If ``boto3`` is not installed (missing ``.[aws]`` extra).
        """
        try:
            import boto3
        except ImportError as error:  # pragma: no cover - exercised via extras-absent CI lane
            raise ConfigurationError(
                "boto3 is required for AwsSecretsManagerProvider; install the 'aws' extra"
            ) from error
        client = boto3.client("secretsmanager", region_name=region_name, endpoint_url=endpoint_url)
        return cls(client)

    async def get_secret(self, name: str) -> SecretStr:
        """Return a cached secret, fetching it from Secrets Manager on first access."""
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
                retry=retry_if_exception(_is_transient),
                reraise=True,
            ):
                with attempt:
                    response = await asyncio.to_thread(
                        self._client.get_secret_value, SecretId=name
                    )
        except Exception as error:
            response = getattr(error, "response", None)
            code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
            if code in {"ResourceNotFoundException", "AccessDeniedException", "InvalidRequestException"}:
                raise ConfigurationError(f"Required secret {name!r} is not configured") from error
            raise DependencyUnavailableError("AWS Secrets Manager is unavailable") from error
        value = response.get("SecretString")
        if not value:
            raise ConfigurationError(f"Required secret {name!r} has no string value")
        return SecretStr(value)

    async def reload(self, names: tuple[str, ...]) -> None:
        """Atomically refresh selected cached values or retain the last valid set."""
        async with self._lock:
            refreshed = {name: await self._fetch(name) for name in names}
            self._cache.update(refreshed)

    async def health_check(self) -> None:
        """Verify Secrets Manager connectivity without reading or logging any value."""
        try:
            await asyncio.to_thread(self._client.list_secrets, MaxResults=1)
        except Exception as error:
            raise DependencyUnavailableError("AWS Secrets Manager is unavailable") from error

    async def close(self) -> None:
        """Drop cached secret material from memory and release the boto3 client."""
        async with self._lock:
            self._cache.clear()
        close = getattr(self._client, "close", None)
        if callable(close):
            await asyncio.to_thread(close)
