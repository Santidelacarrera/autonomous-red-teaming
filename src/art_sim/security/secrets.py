"""Secret-provider boundary for runtime composition without cloud SDK coupling."""

from __future__ import annotations

import os
from typing import Protocol

from pydantic import SecretStr

from art_sim.domain.exceptions import ConfigurationError


class SecretProvider(Protocol):
    """Resolve a named secret without exposing its value to domain services."""

    def get_secret(self, name: str) -> SecretStr:
        """Return a required secret or fail closed when it is unavailable."""


class EnvironmentSecretProvider:
    """Local adapter for environment-injected secrets and development composition roots."""

    def get_secret(self, name: str) -> SecretStr:
        """Read a non-empty environment secret without logging its value."""
        value = os.getenv(name)
        if not value:
            raise ConfigurationError(f"Required secret {name!r} is not configured")
        return SecretStr(value)
