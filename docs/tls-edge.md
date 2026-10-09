# TLS edge configuration

The application never terminates TLS itself — `ProductionDependencySettings` fails closed
unless `ART_TLS_TERMINATED_UPSTREAM=true` (see `src/art_sim/platform/production_config.py`),
and `ART_TRUSTED_PROXY_HOPS` bounds how many proxy hops of `X-Forwarded-*` headers are
trusted for client-IP-derived decisions (rate limiting, audit). TLS termination and
certificate lifecycle are the deployment's edge, configured one of two ways depending on
the target.

## Kubernetes (Helm): Ingress + cert-manager

`deploy/helm/art-sim/templates/ingress.yaml` is disabled by default (`ingress.enabled:
false`) because the chart does not assume a particular ingress controller or that
cert-manager is installed. To enable it:

```yaml
ingress:
  enabled: true
  className: nginx                      # or traefik, or your controller's class
  host: art-sim.example.com
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-production
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  tls:
    enabled: true
    secretName: art-sim-tls              # cert-manager populates this Secret
```

This requires [cert-manager](https://cert-manager.io/) (or an equivalent) with a
`ClusterIssuer`/`Issuer` named by the annotation already installed in the cluster — that
installation is cluster-operator-owned and out of this chart's scope, matching
`docs/production-readiness.md`'s "TLS/API gateway/WAF: READY WITH EXTERNAL DEPENDENCY" row.
`ART_TRUSTED_PROXY_HOPS=1` matches a single ingress-controller hop; add one per additional
load balancer/proxy actually in front of it (e.g. a cloud L7 load balancer ahead of the
ingress controller is a second hop).

Set `networkPolicy.ingressNamespace` (already in `values.yaml`) to the namespace your
ingress controller's pods run in, so the `NetworkPolicy` admits only that traffic.

## docker-compose (non-Kubernetes): Caddy edge

For `docker-compose.prod.yml` deployments, `deploy/edge/` adds a TLS-terminating edge
without a separate ACME client or manually managed certificates:

```bash
mkdir -p deploy/secrets && # ...populate the mounted secrets, see docker-compose.prod.yml...
ART_PUBLIC_HOSTNAME=art-sim.example.com \
  docker compose -f docker-compose.prod.yml -f deploy/edge/docker-compose.edge.yml up -d
```

`deploy/edge/Caddyfile` has Caddy obtain and renew a certificate automatically via ACME
(Let's Encrypt) for `ART_PUBLIC_HOSTNAME`, terminate TLS, forward one proxy hop of plaintext
HTTP to the `api` service over the compose-internal network, and set baseline security
response headers (HSTS, `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`) in front of the application's own (`ART_HSTS_ENABLED=true`). The `api`
service's port stays published to `127.0.0.1` only — the edge container is the only thing
reachable from outside the host.

To use a certificate you already manage instead of ACID/ACME (e.g. one issued by an
internal CA), replace the Caddyfile's site address with an explicit `tls
/certs/fullchain.pem /certs/privkey.pem` directive and mount the certificate files
read-only instead of the `caddy-data` volume.

## What this does not cover

- WAF/DDoS protection at the edge (a cloud provider's L7 load balancer or a dedicated WAF)
  is deployment-owned and not configured here.
- Mutual TLS between the edge and the API is not configured; the compose/Kubernetes network
  boundary is the trust boundary for that one hop, consistent with the rest of this
  repository's adapters being deployment-connected rather than assumed.
