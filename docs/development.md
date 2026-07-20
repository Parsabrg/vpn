# Development guide

The Phase 1.2 workspaces include the runnable Phase 1.1 service shells plus the
control-plane persistence foundation. The API has PostgreSQL models, migrations,
database-backed readiness, and an initial-administrator seed command. It still has
no authentication endpoints, approval workflow, email delivery, VPN provisioning,
WireGuard/Xray runtime integration, or production deployment.

## Pinned toolchain

| Tool    | Version |
| ------- | ------- |
| Python  | 3.14.6  |
| Node.js | 24.18.0 |
| npm     | 11.18.0 |
| Flutter | 3.44.0  |
| Dart    | 3.12.0  |

The root `.tool-versions`, `.python-version`, and `.nvmrc` files are the source of
truth for developer and CI tool versions. Direct application dependencies are
exactly pinned; the admin dependency graph is committed in `package-lock.json`.

## Bootstrap

On a Unix-like development host with the pinned tools installed:

```sh
python -m venv .venv
. .venv/bin/activate
make bootstrap
make check
```

On Windows, activate `.venv\Scripts\Activate.ps1` and run the commands from the
`Makefile` directly if GNU Make is unavailable.

The Flutter workspace intentionally omits generated Android and Windows host
projects until the minimum supported OS versions are confirmed. Shared Dart code,
analysis, and widget tests are already CI-gated.

## Local stack

Copy `.env.example` to `.env` only for local development, then run:

```sh
make compose-smoke
```

Compose starts PostgreSQL with separate least-privilege application and migration
roles. A one-shot `migrate` service upgrades the schema before the API starts. The
application role cannot perform schema migrations.

The stack exposes only loopback development ports:

- admin shell: `http://127.0.0.1:3000`
- API probes: `http://127.0.0.1:8000/healthz` and `/readyz`
- Mailpit: `http://127.0.0.1:8025`

PostgreSQL, Redis, and the mock VPN agent stay on an internal Docker network. The
agent container is read-only, drops every Linux capability, has no host mounts,
and exposes only health probes. It cannot provision a tunnel or execute commands.

Stop the stack with `make compose-down`. Local named volumes contain disposable
development data and must never be treated as backups.

## Database lifecycle

Set `NEBULA_DATABASE_URL` to the application-role connection and
`MIGRATION_DATABASE_URL` to the migration-role connection. Both URLs must use the
`postgresql+psycopg` driver. Then run migrations from the repository root:

```sh
make db-upgrade
make db-check
```

`db-upgrade` applies the checked-in Alembic revisions. `db-check` rejects model
changes that are missing a migration. The `/readyz` endpoint succeeds only when it
can query PostgreSQL and the recorded schema revision exactly matches the
application's expected head.

Create the sole initial owner only after migrations are current:

```sh
cd services/api
nebula-api seed-admin --email admin@example.com
```

The command accepts the password only through two hidden prompts on an interactive
terminal. It never accepts a password argument or environment variable, refuses to
replace an existing owner, and records the creation in the audit log in the same
transaction.

## Quality gates

- Python: Ruff lint/format, strict mypy, pytest, and coverage thresholds for each
  service independently.
- Admin: Prettier, ESLint, strict TypeScript, Vitest, production Next.js build, and
  `npm audit` for production dependencies.
- Mobile: Dart format, Flutter analyze, and Flutter widget tests.
- Database: empty-database upgrade, schema-head verification, downgrade/upgrade
  smoke coverage where safe, and PostgreSQL constraint checks.
- Infrastructure: Compose model validation plus a build-and-health smoke test.
- Supply chain: dependency review, Dependabot, Gitleaks, and Trivy image scans.

GitHub Actions have read-only default permissions and third-party actions are
pinned to full commit SHAs. Production secrets must not be added to CI or local
Compose; use only documented placeholders until a deployment secret mechanism is
approved.
