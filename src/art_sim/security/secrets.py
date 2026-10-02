"""Secret-provider boundary for runtime composition without cloud SDK coupling."""

from __future__ import annotations

import os
from enum import StrEnum
from typing import ClassVar, Protocol

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from art_sim.domain.exceptions import ConfigurationError


class SecretProviderCapability(StrEnum):
    """Trust boundary declared by a secret-provider adapter."""

    ENVIRONMENT = "environment"
    EXTERNAL = "external"


class SecretManagerProvider(StrEnum):
    """Managed secret-service adapter families supported by the port."""

    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    HASHICORP_VAULT = "hashicorp_vault"
    # provider name, not a credential
    GCP_SECRET_MANAGER = "gcp_secret_manager"  # nosec B105
    AZURE_KEY_VAULT = "azure_key_vault"


class SecretManagerSettings(BaseModel):
    """Non-secret configuration for a deployment-owned secret-manager adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: SecretManagerProvider
    approval_hmac_secret_name: str = Field(pattern=r"^[A-Za-z0-9_./-]{3,256}$")
    database_secret_name: str = Field(pattern=r"^[A-Za-z0-9_./-]{3,256}$")
    broker_secret_name: str = Field(pattern=r"^[A-Za-z0-9_./-]{3,256}$")
    oidc_client_secret_name: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_./-]{3,256}$"
    )
    retrieval_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    cache_ttl_seconds: int = Field(default=300, ge=0, le=86_400)

    @model_validator(mode="after")
    def require_distinct_secret_references(self) -> SecretManagerSettings:
        """Prevent accidental reuse of approval, database, and broker credentials."""
        names = {
            self.approval_hmac_secret_name,
            self.database_secret_name,
            self.broker_secret_name,
        }
        if len(names) != 3:
            raise ValueError("approval, database, and broker secrets must be distinct")
        return self


class SecretProvider(Protocol):
    """Resolve a named secret without exposing its value to domain services."""

    deployment_capability: ClassVar[SecretProviderCapability]

    def get_secret(self, name: str) -> SecretStr:
        """Return a required secret or fail closed when it is unavailable."""


class AsyncSecretProvider(Protocol):
    """Resolve secrets asynchronously for managed production backends."""

    deployment_capability: ClassVar[SecretProviderCapability]

    async def get_secret(self, name: str) -> SecretStr:
        """Return a required secret without exposing its value to callers."""


class EnvironmentSecretProvider:
    """Local adapter for environment-injected secrets and development composition roots."""

    deployment_capability: ClassVar[SecretProviderCapability] = (
        SecretProviderCapability.ENVIRONMENT
    )

    def get_secret(self, name: str) -> SecretStr:
        """Read a non-empty environment secret without logging its value."""
        value = os.getenv(name)
        if not value:
            raise ConfigurationError(f"Required secret {name!r} is not configured")
        return SecretStr(value)

class ExternalSecretProvider(AsyncSecretProvider, Protocol):
    """Production port for a stable managed secret source.

    Concrete adapters must declare ``deployment_capability = EXTERNAL`` and keep I/O
    outside domain code. No cloud secret-manager connection is fabricated here.
    """

    async def health_check(self) -> None:
        """Verify provider availability without returning or logging secret values."""

    async def reload(self, names: tuple[str, ...]) -> None:
        """Refresh selected cached values atomically or retain the last valid set."""

    async def close(self) -> None:
        """Release provider resources without exposing cached values."""
