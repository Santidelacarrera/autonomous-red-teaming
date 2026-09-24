# Deployment contract

The supplied Docker image is non-root, excludes `.env`, exposes the documented API port
8080, and checks `/health`. It is a packaging artifact, not an automatic cloud or
Kubernetes deployment.

Production composition must inject: a durable database location, a SecretProvider,
`ART_SIM_APPROVAL_SECRET`, explicit Neo4j Shadow-only settings, dependency probes, and
a structured telemetry logger. Mount persistent storage outside the container for SQLite
or replace the operational ports with a server-database adapter before multi-node use.

Build locally with `docker build -t art-sim:local .`. Do not pass secrets with Dockerfile
instructions; use the deployment platform's secret injection mechanism at runtime.
