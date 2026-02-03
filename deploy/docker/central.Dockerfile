FROM python:3.14-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_CREATE=false

WORKDIR /app

COPY pyproject.toml poetry.lock /app/
RUN pip install --no-cache-dir poetry && \
    poetry install --only central --no-root --no-interaction


FROM python:3.14-slim AS runner

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    git \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local /usr/local
COPY central /app/central
COPY deploy/config /app/config

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "central.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
