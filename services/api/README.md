# Nebula API

Unprivileged FastAPI control-plane service. Phase 1.2 adds the PostgreSQL persistence
foundation while keeping the public HTTP surface limited to liveness and readiness
probes. Business, authentication, and provisioning APIs are added in later
milestones. The container has no host, Docker socket, or VPN secret mounts.

## Development

```shell
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
.venv/bin/uvicorn nebula_api.main:app --reload --port 8000
```

On Windows, replace `.venv/bin/` with `.venv\\Scripts\\`.

Set `NEBULA_DATABASE_URL` to the least-privilege application connection and
`MIGRATION_DATABASE_URL` to the separate migration-role connection. Apply and check
the schema with:

```shell
.venv/bin/alembic upgrade head
.venv/bin/alembic check
```

After migrating, seed the sole initial owner from an interactive terminal:

```shell
.venv/bin/nebula-api seed-admin --email admin@example.com
```

The password is read twice through hidden prompts; no password CLI option or
environment variable is supported.

Probe endpoints are `GET /healthz` and `GET /readyz`. Liveness reports only process
state. Readiness verifies database connectivity and the exact Alembic schema head.
Neither endpoint returns environment values, dependency addresses, credentials, or
host details.
