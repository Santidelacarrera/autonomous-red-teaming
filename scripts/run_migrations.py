"""Run versioned PostgreSQL migrations (Alembic) as a standalone deploy step.

Usage:

    python scripts/run_migrations.py upgrade head
    python scripts/run_migrations.py downgrade -1
    python scripts/run_migrations.py current

This is the production migration path referenced by ``docs/migrations.md`` and the Helm
pre-upgrade hook (``deploy/helm/art-sim/templates/migration-job.yaml``): it runs to
completion and exits *before* any API/worker pod starts against the new schema, which is
what gives migrations an audit trail, ordering guarantees and a real downgrade path that
``PostgresOperationalStore.initialize()``'s idempotent ``CREATE TABLE IF NOT EXISTS`` alone
cannot provide. ``initialize()`` remains a safe no-op bootstrap for local development and
tests; it is not replaced by this script.

The DSN is resolved, in order:

1. ``ART_DATABASE_DSN`` — a pre-resolved environment value (e.g. injected by a Vault Agent
   sidecar or a Kubernetes-mounted secret projected directly as an env var).
2. The configured secret provider (``ART_SECRET_PROVIDER`` + ``ART_DATABASE_DSN_SECRET_NAME``
   + ``ART_SECRETS_DIR`` for the mounted provider), resolved the same way the API composition
   root resolves it, so this script never invents a second way to reach a secret.

No secret value is logged. This script requires the ``migrations`` extra
(``pip install .[migrations]``).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config


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
        raise RuntimeError(f"Unsupported ART_SECRET_PROVIDER for migrations: {provider_name!r}")

    try:
        dsn = await provider.get_secret(secret_name)
        return dsn.get_secret_value()
    finally:
        await provider.close()


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    dsn = asyncio.run(_resolve_dsn())
    os.environ["ART_DATABASE_DSN"] = dsn

    repo_root = Path(__file__).resolve().parent.parent
    config = Config(str(repo_root / "alembic.ini"))
    config.set_main_option("script_location", str(repo_root / "migrations"))

    action, *rest = argv
    if action == "upgrade":
        command.upgrade(config, rest[0] if rest else "head")
    elif action == "downgrade":
        command.downgrade(config, rest[0] if rest else "-1")
    elif action == "current":
        command.current(config, verbose=True)
    elif action == "history":
        command.history(config, verbose=True)
    else:
        print(f"Unsupported action {action!r}; use upgrade|downgrade|current|history")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
