# Nebula API

Unprivileged FastAPI control-plane service. Phase 1.3 adds separate user bearer-token
and administrator cookie/MFA authentication realms on the Phase 1.2 PostgreSQL
foundation. The container still has no host, Docker socket, or VPN secret mounts.

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

Authentication also requires `NEBULA_REDIS_URL`. Staging and production require all
four authentication key files: an Ed25519 private/public PEM pair, a raw 32-byte
token pepper, and a raw 32-byte MFA encryption key. Development and tests generate
process-local keys only when none of those paths is configured. Those ephemeral
keys are intentionally unsuitable for multiple workers or persistent local data:
restarting the process invalidates access/refresh/reset material and makes existing
MFA ciphertext unreadable. See [`../../docs/environment.md`](../../docs/environment.md).

User routes under `/v1/auth` provide login, refresh rotation, idempotent logout,
current-principal lookup, and password-reset request/confirmation. Administrator
routes under `/v1/admin/auth` provide password challenge, first-time TOTP enrollment,
TOTP or recovery-code verification, current session, step-up, logout, and recovery-
code rotation. Administrator mutations require an exact allowed origin, JSON, the
HttpOnly session cookie, and the matching rotating CSRF token. The default app has
no password-reset delivery adapter; the neutral request endpoint does not issue a
usable reset until Phase 1.4 supplies that protected boundary.

Probe endpoints are `GET /healthz` and `GET /readyz`. Liveness reports only process
state. Readiness verifies PostgreSQL connectivity, the exact Alembic schema head,
and Redis connectivity. Neither endpoint returns environment values, dependency
addresses, credentials, or host details.
