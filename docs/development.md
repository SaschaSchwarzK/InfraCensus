# Development

## Requirements

- Python 3.12+ recommended for local development.
- Poetry for dependency management.
- Docker for containerized workflows.

## Local Commands

- `poetry install` installs dependencies.
- `poetry run scripts/run_api.sh` starts the central API on port 8000.
- `poetry run scripts/run_collector.sh` starts a collector process.
- `alembic upgrade head` applies database migrations.
- `SCANNER_PLUGIN=snmp scripts/run_collector.sh` switches the active scanner.
- `http://localhost:8000/` serves the GUI pages.
- `http://localhost:8000/login` is the login page.

## Migrations

Generate a new migration after model changes:

```bash
alembic revision --autogenerate -m "describe change"
```

## Directory Conventions

- Central services live under `central/`.
- Collector logic lives under `collector/`.
- Shared scripts belong in `scripts/`.
- Plugin defaults live in `central/core/plugins.py`.
- GUI templates live in `central/web/templates`.

## Access Model

- Superadmins still require tenant membership and roles for tenant access.
- Use `central/core/auth.py` helpers to enforce RO/RW/User Admin checks.

## OIDC Configuration

- Set `settings.auth_mode` to `oidc` and configure `oidc_issuer_url`, `oidc_client_id`, `oidc_client_secret`.
- Default scopes: `openid email profile`.
- Users are matched by email; new logins are created without local passwords.
