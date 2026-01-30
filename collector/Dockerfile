FROM python:3.14-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_CREATE=false

WORKDIR /app

COPY pyproject.toml poetry.lock /app/
RUN pip install --no-cache-dir poetry && \
    poetry install --only collector --no-root --no-interaction


FROM python:3.14-slim AS runner

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    openssl \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local /usr/local
COPY collector /app/collector
COPY deploy/config /app/config

RUN useradd -m -u 1000 collector && \
    mkdir -p /collector/data /collector/certs && \
    chown -R collector:collector /collector

USER collector

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

CMD ["python", "-m", "collector.agent.main"]
