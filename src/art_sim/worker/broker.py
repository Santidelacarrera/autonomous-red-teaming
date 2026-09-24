"""Provider-neutral production broker configuration and failure taxonomy."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from art_sim.domain.exceptions import (
    DependencyNotConfiguredError,
    DependencyOperationError,
    DependencyUnavailableError,
)
from art_sim.worker.retry import TransientAdapterError


class BrokerProvider(StrEnum):
    """Supported deployment adapter families; no connection is implied."""

    REDIS_STREAMS = "redis_streams"
    RABBITMQ = "rabbitmq"
    KAFKA = "kafka"
    AWS_SQS = "aws_sqs"


class BrokerSettings(BaseModel):
    """Non-secret broker settings consumed by a deployment-owned adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: BrokerProvider
    endpoint: str = Field(min_length=3, max_length=1024)
    queue_name: str = Field(pattern=r"^[A-Za-z0-9._/-]{1,128}$")
    credential_secret_name: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    operation_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    visibility_timeout_seconds: int = Field(default=300, ge=10, le=43_200)
    max_in_flight: int = Field(default=64, ge=1, le=10_000)
    max_delivery_attempts: int = Field(default=5, ge=1, le=100)
    shutdown_grace_seconds: float = Field(default=30.0, ge=1.0, le=300.0)

    @field_validator("endpoint")
    @classmethod
    def endpoint_must_not_embed_credentials(cls, value: str) -> str:
        """Reject endpoints that could leak credentials through configuration output."""
        if "@" in value or "?" in value or "#" in value:
            raise ValueError("broker endpoint must not embed credentials or query parameters")
        schemes = ("redis://", "rediss://", "amqp://", "amqps://", "kafka://", "https://")
        if not value.startswith(schemes):
            raise ValueError("broker endpoint scheme is not supported")
        return value.rstrip("/")

    @model_validator(mode="after")
    def enforce_visibility_window(self) -> BrokerSettings:
        """Keep visibility long enough to exceed an individual operation timeout."""
        if self.visibility_timeout_seconds <= self.operation_timeout_seconds:
            raise ValueError("visibility timeout must exceed operation timeout")
        return self


class BrokerHealth(BaseModel):
    """Safe broker readiness result without hostnames, credentials, or payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: BrokerProvider
    ready: bool


class BrokerNotConfiguredError(DependencyNotConfiguredError):
    """No broker adapter/configuration was supplied to distributed composition."""

    public_code = "BROKER_NOT_CONFIGURED"


class BrokerUnavailableError(TransientAdapterError, DependencyUnavailableError):
    """The configured broker could not be reached within its bounded timeout."""

    public_code = "BROKER_UNAVAILABLE"


class BrokerOperationError(DependencyOperationError):
    """The broker was reached but could not complete a requested operation."""

    public_code = "BROKER_OPERATION_FAILED"
