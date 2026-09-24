"""Phase 13 production boundaries and controlled failure-injection tests."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar
from uuid import UUID

import pytest
from dotenv import dotenv_values
from pydantic import ValidationError

from art_sim.platform.database import ServerDatabaseSettings
from art_sim.platform.health import HealthService
from art_sim.platform.models import SimulationRun
from art_sim.platform.production_config import ProductionDependencySettings
from art_sim.platform.sqlite import SqliteOperationalStore
from art_sim.security.audit import AuditRetentionPolicy
from art_sim.security.secrets import SecretManagerProvider, SecretManagerSettings
from art_sim.worker.broker import (
    BrokerHealth,
    BrokerNotConfiguredError,
    BrokerOperationError,
    BrokerProvider,
    BrokerSettings,
    BrokerUnavailableError,
)
from art_sim.worker.dispatcher import BrokerSimulationDispatcher
from art_sim.worker.jobs import SimulationJobV1
from art_sim.worker.retry import RetryPolicy, TransientAdapterError


class _UnavailableTransport:
    """Controlled transport that never connects to external infrastructure."""

    provider: ClassVar[BrokerProvider] = BrokerProvider.KAFKA

    def __init__(self, failure: Exception) -> None:
        self._failure = failure

    async def publish(self, job: SimulationJobV1, deduplication_key: str) -> bool:
        del job, deduplication_key
        raise self._failure

    async def publish_cancellation(self, run_id: UUID, correlation_id: str) -> bool:
        del run_id, correlation_id
        raise self._failure

    async def health_check(self) -> BrokerHealth:
        raise self._failure

    async def close(self) -> None:
        return None


class _UnusedStore:
    """Store stub that proves broker configuration fails before durable I/O."""


def test_broker_settings_reject_embedded_credentials() -> None:
    """Broker credentials must be referenced by name, never embedded in endpoints."""
    with pytest.raises(ValidationError, match="embed credentials"):
        BrokerSettings(
            provider=BrokerProvider.RABBITMQ,
            endpoint="amqps://user:password@broker.example.com",
            queue_name="simulation-jobs",
            credential_secret_name="ART_BROKER_SECRET",
        )


def test_distributed_dispatcher_distinguishes_missing_broker() -> None:
    """Absent configuration has a stable code distinct from runtime failure."""
    with pytest.raises(BrokerNotConfiguredError) as captured:
        BrokerSimulationDispatcher(_UnusedStore(), None)  # type: ignore[arg-type]
    assert captured.value.public_code == "BROKER_NOT_CONFIGURED"


async def test_broker_failure_taxonomy_is_safe_and_deterministic(tmp_path: Path) -> None:
    """Transient and non-transient broker failures cannot collapse into one state."""
    policy = RetryPolicy(
        max_attempts=1,
        initial_backoff_seconds=0,
        maximum_backoff_seconds=0,
        jitter_ratio=0,
    )
    unavailable = BrokerSimulationDispatcher(
        _UnusedStore(),  # type: ignore[arg-type]
        _UnavailableTransport(TransientAdapterError("sensitive host detail")),
        retry_policy=policy,
    )
    with pytest.raises(BrokerUnavailableError) as unavailable_error:
        await unavailable.health_check()
    assert unavailable_error.value.public_code == "BROKER_UNAVAILABLE"
    assert "sensitive host detail" not in str(unavailable_error.value)

    failed = BrokerSimulationDispatcher(
        _UnusedStore(),  # type: ignore[arg-type]
        _UnavailableTransport(ValueError("sensitive broker response")),
        retry_policy=policy,
    )
    with pytest.raises(BrokerUnavailableError):
        await failed.health_check()

    store = SqliteOperationalStore(tmp_path / "broker-errors.sqlite3")
    await store.initialize()
    run = SimulationRun(
        scenario_id="shadow-demo",
        graph_version="unresolved",
        workflow_version="v1",
        created_by="phase13-test",
    )
    await store.create_run(run)
    operation = BrokerSimulationDispatcher(
        store,
        _UnavailableTransport(ValueError("sensitive broker response")),
        retry_policy=policy,
    )
    with pytest.raises(BrokerOperationError) as operation_error:
        await operation.dispatch(run.run_id)
    assert operation_error.value.public_code == "BROKER_OPERATION_FAILED"
    assert "sensitive broker response" not in str(operation_error.value)


async def test_readiness_reports_each_unavailable_dependency_without_details() -> None:
    """External outages affect readiness while liveness remains healthy."""

    async def healthy() -> None:
        return None

    async def unavailable() -> None:
        raise BrokerUnavailableError("credential=must-not-appear")

    service = HealthService(
        {
            "database": unavailable,
            "broker": unavailable,
            "secret_provider": unavailable,
            "identity_provider": healthy,
            "rate_limiter": healthy,
            "audit": unavailable,
            "telemetry": unavailable,
        }
    )
    assert (await service.health()).model_dump() == {
        "status": "ok",
        "checks": {"process": "ok"},
    }
    readiness = await service.readiness()
    assert readiness.status == "not_ready"
    assert readiness.checks["identity_provider"] == "ok"
    assert {
        name for name, status in readiness.checks.items() if status == "unavailable"
    } == {"database", "broker", "secret_provider", "audit", "telemetry"}
    assert "credential" not in readiness.model_dump_json()


def test_secret_database_and_retention_configuration_fail_closed() -> None:
    """Invalid security/coordination configuration is rejected before startup."""
    with pytest.raises(ValidationError, match="must be distinct"):
        SecretManagerSettings(
            provider=SecretManagerProvider.AWS_SECRETS_MANAGER,
            approval_hmac_secret_name="shared/secret",
            database_secret_name="shared/secret",
            broker_secret_name="broker/secret",
        )
    with pytest.raises(ValidationError, match="minimum"):
        ServerDatabaseSettings(
            dsn_secret_name="ART_DATABASE_DSN",
            pool_min_size=20,
            pool_max_size=2,
        )
    with pytest.raises(ValidationError, match="precede"):
        AuditRetentionPolicy(retention_days=30, archive_after_days=30)


def test_production_example_contains_valid_references_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tracked production example remains synchronized with the strict loader."""
    root = Path(__file__).resolve().parents[2]
    values = dotenv_values(root / ".env.production.example")
    for name, value in values.items():
        if name.startswith("ART_") and value is not None:
            monkeypatch.setenv(name, value)
    settings = ProductionDependencySettings.from_environment()
    assert settings.tls_terminated_upstream
    assert settings.database.dsn_secret_name == "ART_DATABASE_DSN"
    serialized = settings.model_dump_json()
    assert "password" not in serialized.lower()
    assert "client-secret-value" not in serialized
