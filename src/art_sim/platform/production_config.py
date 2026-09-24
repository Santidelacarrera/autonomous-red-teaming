"""Explicit provider-neutral production dependency configuration."""

from __future__ import annotations

import os
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from art_sim.domain.exceptions import ConfigurationError
from art_sim.platform.database import ServerDatabaseProvider, ServerDatabaseSettings
from art_sim.security.audit import AuditRetentionPolicy
from art_sim.security.secrets import SecretManagerProvider, SecretManagerSettings
from art_sim.worker.broker import BrokerProvider, BrokerSettings


class DistributedRateLimitProvider(StrEnum):
    """Deployment families capable of enforcing limits across API replicas."""

    REDIS = "redis"
    API_GATEWAY = "api_gateway"
    REVERSE_PROXY = "reverse_proxy"
    SERVICE_MESH = "service_mesh"


class TelemetryProvider(StrEnum):
    """External telemetry integration families."""

    OTLP = "otlp"
    PROMETHEUS = "prometheus"
    MANAGED = "managed"


class DurableAuditProvider(StrEnum):
    """Durable audit integration families."""

    SIEM = "siem"
    EVENT_STREAM = "event_stream"
    IMMUTABLE_STORE = "immutable_store"


class DataRetentionSettings(BaseModel):
    """Configurable lifecycle limits; no jurisdiction-specific defaults are inferred."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    simulation_days: int = Field(ge=1, le=3650)
    result_artifact_days: int = Field(ge=1, le=3650)
    checkpoint_days: int = Field(ge=1, le=3650)
    dead_letter_days: int = Field(ge=1, le=3650)
    telemetry_days: int = Field(ge=1, le=3650)


class ProductionDependencySettings(BaseModel):
    """Complete non-secret contract required before production composition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    broker: BrokerSettings
    database: ServerDatabaseSettings
    secrets: SecretManagerSettings
    audit_provider: DurableAuditProvider
    audit_retention: AuditRetentionPolicy
    telemetry_provider: TelemetryProvider
    rate_limit_provider: DistributedRateLimitProvider
    retention: DataRetentionSettings
    tls_terminated_upstream: bool
    trusted_proxy_hops: int = Field(ge=1, le=10)
    request_timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    max_request_bytes: int = Field(default=65_536, ge=1024, le=1_048_576)

    @model_validator(mode="after")
    def require_tls(self) -> ProductionDependencySettings:
        """Fail closed when the API edge does not terminate TLS."""
        if not self.tls_terminated_upstream:
            raise ValueError("production requires upstream TLS termination")
        return self

    @classmethod
    def from_environment(cls) -> ProductionDependencySettings:
        """Load required non-secret production references and fail closed if incomplete."""
        try:
            audit_days = _required_int("ART_AUDIT_RETENTION_DAYS")
            archive_value = os.getenv("ART_AUDIT_ARCHIVE_AFTER_DAYS")
            return cls(
                broker=BrokerSettings(
                    provider=BrokerProvider(_required("ART_BROKER_PROVIDER")),
                    endpoint=_required("ART_BROKER_ENDPOINT"),
                    queue_name=_required("ART_BROKER_QUEUE"),
                    credential_secret_name=_required("ART_BROKER_CREDENTIAL_SECRET_NAME"),
                    operation_timeout_seconds=_float("ART_BROKER_TIMEOUT_SECONDS", 5.0),
                    visibility_timeout_seconds=_int("ART_BROKER_VISIBILITY_SECONDS", 300),
                    max_in_flight=_int("ART_BROKER_MAX_IN_FLIGHT", 64),
                    max_delivery_attempts=_int("ART_BROKER_MAX_DELIVERY_ATTEMPTS", 5),
                ),
                database=ServerDatabaseSettings(
                    provider=ServerDatabaseProvider(
                        os.getenv("ART_DATABASE_PROVIDER", "postgresql")
                    ),
                    dsn_secret_name=_required("ART_DATABASE_DSN_SECRET_NAME"),
                    pool_min_size=_int("ART_DATABASE_POOL_MIN", 2),
                    pool_max_size=_int("ART_DATABASE_POOL_MAX", 20),
                    connect_timeout_seconds=_float("ART_DATABASE_CONNECT_TIMEOUT_SECONDS", 5.0),
                    statement_timeout_seconds=_float(
                        "ART_DATABASE_STATEMENT_TIMEOUT_SECONDS", 30.0
                    ),
                ),
                secrets=SecretManagerSettings(
                    provider=SecretManagerProvider(_required("ART_SECRET_PROVIDER")),
                    approval_hmac_secret_name=_required("ART_APPROVAL_SECRET_NAME"),
                    database_secret_name=_required("ART_DATABASE_DSN_SECRET_NAME"),
                    broker_secret_name=_required("ART_BROKER_CREDENTIAL_SECRET_NAME"),
                    oidc_client_secret_name=os.getenv("ART_OIDC_CLIENT_SECRET_NAME"),
                ),
                audit_provider=DurableAuditProvider(_required("ART_AUDIT_PROVIDER")),
                audit_retention=AuditRetentionPolicy(
                    retention_days=audit_days,
                    archive_after_days=int(archive_value) if archive_value else None,
                ),
                telemetry_provider=TelemetryProvider(_required("ART_TELEMETRY_PROVIDER")),
                rate_limit_provider=DistributedRateLimitProvider(
                    _required("ART_RATE_LIMIT_PROVIDER")
                ),
                retention=DataRetentionSettings(
                    simulation_days=_required_int("ART_SIMULATION_RETENTION_DAYS"),
                    result_artifact_days=_required_int("ART_RESULT_RETENTION_DAYS"),
                    checkpoint_days=_required_int("ART_CHECKPOINT_RETENTION_DAYS"),
                    dead_letter_days=_required_int("ART_DEAD_LETTER_RETENTION_DAYS"),
                    telemetry_days=_required_int("ART_TELEMETRY_RETENTION_DAYS"),
                ),
                tls_terminated_upstream=_bool("ART_TLS_TERMINATED_UPSTREAM", False),
                trusted_proxy_hops=_required_int("ART_TRUSTED_PROXY_HOPS"),
                request_timeout_seconds=_float("ART_REQUEST_TIMEOUT_SECONDS", 30.0),
                max_request_bytes=_int("ART_MAX_REQUEST_BYTES", 65_536),
            )
        except (TypeError, ValueError) as error:
            raise ConfigurationError("Production dependency configuration is invalid") from error


def _required(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise ConfigurationError(f"Required production setting {name!r} is absent")
    return value.strip()


def _required_int(name: str) -> int:
    return int(_required(name))


def _int(name: str, default: int) -> int:
    value = os.getenv(name)
    return default if value is None else int(value)


def _float(name: str, default: float) -> float:
    value = os.getenv(name)
    return default if value is None else float(value)


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    if value.lower() not in {"true", "false", "1", "0"}:
        raise ConfigurationError(f"{name} must be true or false")
    return value.lower() in {"true", "1"}
