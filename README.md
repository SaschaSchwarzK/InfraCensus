# InfraCensus

InfraCensus is a network infrastructure discovery and inventory platform with a central control plane and distributed collectors. The central API manages collectors, schedules scans, aggregates results, and exposes data for plugins and exports.

## Project Structure

- `central/` - Central API, core logic, database access, plugins, and web UI.
- `collector/` - Lightweight collectors for discovery and data collection.
- `deploy/` - Docker and Kubernetes deployment assets.
- `docs/` - Architecture and development documentation.
- `scripts/` - Local dev helpers.
- `tests/` - Unit, integration, and end-to-end tests.

## Quickstart (Local)

```bash
poetry install
poetry run scripts/run_api.sh
```

Collector (separate terminal):

```bash
poetry run scripts/run_collector.sh
```

## Docker Compose

```bash
docker compose up --build
```

