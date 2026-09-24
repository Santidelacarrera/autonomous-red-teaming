"""Validated runtime selection for development, staging, and production composition."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from art_sim.domain.exceptions import ConfigurationError
from art_sim.security.secrets import SecretProvider


class RuntimeEnvironment(StrEnum):
    """Allowed deployment profiles; production is never inferred implicitly."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class OperationalSettings(BaseModel):
    """Non-secret runtime choices validated before a worker begins accepting runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: RuntimeEnvironment = RuntimeEnvironment.DEVELOPMENT
    operational_database: Path = Path("var/art-sim/operations.sqlite3")
    approval_secret_name: str = Field(default="ART_SIM_APPROVAL_SECRET", pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    workflow_version: str = Field(default="v1", pattern=r"^[A-Za-z0-9._-]{1,64}$")
    logging_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR)$")

    @field_validator("operational_database")
    @classmethod
    def database_must_be_relative_or_explicit_file(cls, value: Path) -> Path:
        """Reject directory paths and require an explicit SQLite file suffix."""
        if value.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
            raise ValueError("operational_database must name a SQLite database file")
        return value

    def approval_secret(self, provider: SecretProvider) -> bytes:
        """Resolve and validate signing material before starting a sensitive workflow."""
        value = provider.get_secret(self.approval_secret_name).get_secret_value().encode("utf-8")
        if len(value) < 32:
            raise ConfigurationError("approval secret must contain at least 32 bytes")
        return value
