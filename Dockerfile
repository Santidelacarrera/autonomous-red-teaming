FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements-runtime.lock ./
RUN python -m pip install --prefix=/install --no-compile -r requirements-runtime.lock

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --prefix=/install --no-deps --no-compile .

FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

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
