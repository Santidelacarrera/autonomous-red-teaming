FROM python:3.13.16-slim-trixie@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements-runtime.lock ./
# --require-hashes enforces that every pinned dependency matches a recorded hash,
# failing the build loudly if the lock is tampered with or a hash is missing.
#
# Behind a TLS-intercepting proxy the build container does not trust the proxy CA. Supply it as a
# BuildKit *secret* (never baked into a layer):
#   docker build --secret id=ca_bundle,src=/path/to/ca-bundle.crt .
# Without the secret this step behaves exactly as before. TLS verification is never disabled.
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi \
    && python -m pip install --prefix=/install --no-compile --require-hashes -r requirements-runtime.lock

COPY pyproject.toml README.md ./
COPY src ./src
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi \
    && python -m pip install --prefix=/install --no-deps --no-compile .

FROM python:3.13.16-slim-trixie@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Patch OS packages that ship with an available security fix (e.g. openssl/libssl3,
# libpcre2) before dropping privileges. This closes every Debian CVE for which an
# upstream fix exists at build time; CVEs with no published fix are governed by the
# only-fixed scan policy and the documented dispositions in .grype.yaml.
#
# OS_UPGRADE=false skips this for functional-only local builds where the Debian mirrors are not
# reachable (e.g. an egress-restricted sandbox). Such an image has NOT been patched and must never
# be released or pushed: CI and release builds always use the default (true).
ARG OS_UPGRADE=true
RUN if [ "$OS_UPGRADE" = "true" ]; then \
        apt-get update \
        && apt-get upgrade -y --no-install-recommends \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*; \
    fi

RUN groupadd --gid 10001 appuser \
    && useradd --no-create-home --uid 10001 --gid 10001 --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/var \
    && chown -R 10001:10001 /app/var

WORKDIR /app
COPY --from=builder /install /usr/local

USER appuser
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/health', timeout=3).read()" || exit 1

EXPOSE 8080
STOPSIGNAL SIGTERM
CMD ["uvicorn", "art_sim.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
