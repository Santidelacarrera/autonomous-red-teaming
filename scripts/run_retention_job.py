"""Run the automated data-retention purge job (``art_sim.retention.job.RetentionJob``).

Usage:

    python scripts/run_retention_job.py --dry-run     # report only, deletes nothing
    python scripts/run_retention_job.py --execute     # deletes expired records for real

This is the executable enforcement of the policy table in docs/data-retention.md: it reads
the same ``ART_*_RETENTION_DAYS`` values the production composition root validates at
startup (``ProductionDependencySettings.retention``), builds the real PostgreSQL store and
(if configured) Redis broker adapters, and runs ``RetentionJob``. Every run — dry or real —
is written to the configured durable audit sink.

Intended to run as the Helm CronJob (`deploy/helm/art-sim/templates/retention-cronjob.yaml`,
disabled by default — an operator must confirm the configured windows match policy first)
or manually via `make retention-job-dry-run` / `make retention-job`.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

import asyncpg

from art_sim.adapters.postgres_store import PostgresOperationalStore
from art_sim.platform.production_config import DataRetentionSettings
from art_sim.retention.job import RetentionJob
from art_sim.security.audit import AuditRetentionPolicy


async def _resolve_dsn() -> str:
    pre_resolved = os.environ.get("ART_DATABASE_DSN")
    if pre_resolved:
        return pre_resolved
    provider_name = os.environ.get("ART_SECRET_PROVIDER")
    secret_name = os.environ.get("ART_DATABASE_DSN_SECRET_NAME")
    if not provider_name or not secret_name:
        raise RuntimeError(
            "Set ART_DATABASE_DSN directly, or ART_SECRET_PROVIDER + "
            "ART_DATABASE_DSN_SECRET_NAME so this script can resolve it"
        )
    if provider_name == "mounted":
        from art_sim.adapters.mounted_secret_provider import MountedSecretsProvider

        secrets_dir = os.environ.get("ART_SECRETS_DIR", "/run/secrets")
        provider = MountedSecretsProvider(Path(secrets_dir))
    elif provider_name == "aws_secrets_manager":
        from art_sim.adapters.aws_secrets_manager_provider import AwsSecretsManagerProvider

        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise RuntimeError("AWS_REGION is required for ART_SECRET_PROVIDER=aws_secrets_manager")
        provider = AwsSecretsManagerProvider.from_region(region)
    elif provider_name == "hashicorp_vault":
        from art_sim.adapters.vault_secret_provider import VaultSecretProvider

        vault_addr = os.environ.get("VAULT_ADDR")
        vault_token = os.environ.get("VAULT_TOKEN")
        if not vault_addr or not vault_token:
            raise RuntimeError(
                "VAULT_ADDR and VAULT_TOKEN are required for ART_SECRET_PROVIDER=hashicorp_vault"
            )
        provider = VaultSecretProvider.from_url(
            vault_addr, vault_token, mount_point=os.environ.get("VAULT_KV_MOUNT", "secret")
        )
    else:
        raise RuntimeError(f"Unsupported ART_SECRET_PROVIDER for the retention job: {provider_name!r}")
    try:
        dsn = await provider.get_secret(secret_name)
        return dsn.get_secret_value()
    finally:
        await provider.close()


def _retention_settings_from_environment() -> DataRetentionSettings:
    def _required_int(name: str) -> int:
        value = os.environ.get(name)
        if not value:
            raise RuntimeError(f"Required retention setting {name!r} is absent")
        return int(value)

    return DataRetentionSettings(
        simulation_days=_required_int("ART_SIMULATION_RETENTION_DAYS"),
        result_artifact_days=_required_int("ART_RESULT_RETENTION_DAYS"),
        checkpoint_days=_required_int("ART_CHECKPOINT_RETENTION_DAYS"),
        dead_letter_days=_required_int("ART_DEAD_LETTER_RETENTION_DAYS"),
        telemetry_days=_required_int("ART_TELEMETRY_RETENTION_DAYS"),
    )


async def _build_audit_sink() -> object | None:
    """Best-effort durable audit sink; a missing/misconfigured one must not block the job."""
    audit_path = os.environ.get("ART_AUDIT_PATH")
    if not audit_path:
        return None
    from art_sim.adapters.jsonl_audit_sink import JsonlDurableSecurityAuditSink

    retention_days = int(os.environ.get("ART_AUDIT_RETENTION_DAYS", "365"))
    return JsonlDurableSecurityAuditSink(
        Path(audit_path), AuditRetentionPolicy(retention_days=retention_days)
    )


async def _run(dry_run: bool) -> int:
    dsn = await _resolve_dsn()
    settings = _retention_settings_from_environment()
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
    store = PostgresOperationalStore(pool)
    audit_sink = await _build_audit_sink()

    broker = None
    broker_endpoint = os.environ.get("ART_BROKER_ENDPOINT")
    if broker_endpoint and broker_endpoint.startswith(("redis://", "rediss://")):
        from art_sim.adapters.redis_streams_broker import RedisStreamsBrokerTransport

        broker = RedisStreamsBrokerTransport.from_url(broker_endpoint)

    job = RetentionJob(store, settings, broker=broker, audit_sink=audit_sink)
    try:
        report = await job.run(dry_run=dry_run)
    finally:
        await store.close()
        if broker is not None:
            await broker.close()
        if audit_sink is not None:
            await audit_sink.close()

    mode = "DRY-RUN (nothing deleted)" if report.dry_run else "EXECUTED"
    print(
        f"Retention job {mode} at {report.executed_at.isoformat()}: "
        f"runs={report.runs_purged} checkpoints={report.checkpoints_purged} "
        f"results={report.results_purged} dead_letter={report.dead_letter_purged} "
        f"total={report.total_purged}"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="report what would be deleted")
    group.add_argument("--execute", action="store_true", help="actually delete expired records")
    args = parser.parse_args(argv)
    return asyncio.run(_run(dry_run=not args.execute))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
