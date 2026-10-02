FROM python:3.13.15-slim-trixie@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements-runtime.lock ./
RUN python -m pip install --prefix=/install --no-compile -r requirements-runtime.lock

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --prefix=/install --no-deps --no-compile .

FROM python:3.13.15-slim-trixie@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Patch OS packages that ship with an available security fix (e.g. openssl/libssl3,
# libpcre2) before dropping privileges. This closes every Debian CVE for which an
# upstream fix exists at build time; CVEs with no published fix are governed by the
# only-fixed scan policy and the documented dispositions in .grype.yaml.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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
