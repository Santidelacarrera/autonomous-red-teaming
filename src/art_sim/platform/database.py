"""Server-grade operational database configuration boundary."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ServerDatabaseProvider(StrEnum):
    """Supported adapter families without claiming that an adapter is installed."""

    POSTGRESQL = "postgresql"
    EQUIVALENT = "equivalent"


class ServerDatabaseSettings(BaseModel):
    """Non-secret settings for a transactional multi-worker operational store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ServerDatabaseProvider = ServerDatabaseProvider.POSTGRESQL
    dsn_secret_name: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    pool_min_size: int = Field(default=2, ge=1, le=100)
    pool_max_size: int = Field(default=20, ge=1, le=500)
    connect_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    statement_timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    application_name: str = Field(default="art-sim", pattern=r"^[A-Za-z0-9._-]{1,64}$")

    @model_validator(mode="after")
    def validate_pool_bounds(self) -> ServerDatabaseSettings:
        """Reject an internally inconsistent connection-pool configuration."""
        if self.pool_min_size > self.pool_max_size:
            raise ValueError("database pool minimum cannot exceed maximum")
        return self
