"""Secret-provider boundary for runtime composition without cloud SDK coupling."""

from __future__ import annotations

import os
from enum import StrEnum
from typing import ClassVar, Protocol

from pydantic import SecretStr

from art_sim.domain.exceptions import ConfigurationError


class SecretProviderCapability(StrEnum):
    """Trust boundary declared by a secret-provider adapter."""

    ENVIRONMENT = "environment"
    EXTERNAL = "external"


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
