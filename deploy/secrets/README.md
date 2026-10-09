# Mounted secrets (local only)

This directory is git-ignored. Create one file per secret name for the
production-like Docker Compose stack:

```bash
openssl rand -hex 32 > ART_SIM_APPROVAL_SECRET
printf 'postgresql://artsim:artsim@postgres:5432/artsim' > ART_DATABASE_DSN
printf 'redis://redis:6379/1' > ART_BROKER_CREDENTIAL
```

Never commit real secrets. In Kubernetes these come from a projected Secret volume.
