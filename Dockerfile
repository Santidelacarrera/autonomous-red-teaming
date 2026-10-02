FROM python:3.14.0-slim-trixie@sha256:0aecac02dc3d4c5dbb024b753af084cafe41f5416e02193f1ce345d671ec966e AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements-runtime.lock ./
# --require-hashes enforces that every pinned dependency matches a recorded hash,
# failing the build loudly if the lock is tampered with or a hash is missing.
RUN python -m pip install --prefix=/install --no-compile --require-hashes -r requirements-runtime.lock

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --prefix=/install --no-deps --no-compile .

FROM python:3.14.0-slim-trixie@sha256:0aecac02dc3d4c5dbb024b753af084cafe41f5416e02193f1ce345d671ec966e AS runtime

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
