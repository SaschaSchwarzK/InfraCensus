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

## Configuration

InfraCensus supports configuration via environment variables, YAML files, or Git-backed YAML.

### YAML (Local)

- Central: set `CENTRAL_CONFIG_FILE=deploy/config/central.yaml`
- Collector: set `COLLECTOR_CONFIG_FILE=deploy/config/collector.yaml`

Example configs live in `deploy/config/central.yaml` and `deploy/config/collector.yaml`.

### Git (Optional)

- Central: set `CENTRAL_CONFIG_GIT_URL`, `CENTRAL_CONFIG_GIT_REF`, and `CENTRAL_CONFIG_GIT_PATH`
- Collector: set `COLLECTOR_CONFIG_GIT_URL`, `COLLECTOR_CONFIG_GIT_REF`, and `COLLECTOR_CONFIG_GIT_PATH`

By default the central API polls for changes every 60 seconds when Git config is enabled.
Override polling with `CONFIG_POLL_SECONDS`.

### Docker

The Docker images include example configs at `/app/config/central.yaml` and `/app/config/collector.yaml`.

### Security Notes

- In non-dev environments, `SESSION_SECRET` must be set and at least 32 characters.
- Set `REQUIRE_VAULT=true` to enforce Vault-backed credentials.

## Docker Compose

```bash
docker compose up --build
```
