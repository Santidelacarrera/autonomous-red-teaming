# Deployment contract

The supplied Docker image is non-root, excludes `.env`, exposes the documented API port
8080, and checks `/health`. It is a packaging artifact, not an automatic cloud or
Kubernetes deployment.

Development may mount persistent SQLite storage. Production composition rejects SQLite
and requires a `SERVER_GRADE` operational store, distributed dispatcher, externally
deployed workers, external async secret provider, distributed limiter, durable audit,
external telemetry, OIDC, and TLS/CORS/HSTS configuration. The repository supplies
contracts but no fabricated broker, PostgreSQL, secret-manager, or telemetry connection.

Build locally with `docker build -t art-sim:local .`. Do not pass secrets with Dockerfile
instructions; use the deployment platform's secret injection mechanism at runtime.
The supplied command starts the development composition; setting a production profile
causes that entry point to fail closed rather than start the local dispatcher.
