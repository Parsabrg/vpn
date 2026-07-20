# Development guide

The Phase 1.1 workspaces are runnable scaffolds. They provide probes, placeholder
interfaces, tests, and build boundaries; they do not provide authentication,
database models, email delivery, WireGuard, Xray, or production deployment.

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

The stack exposes only loopback development ports:

- admin shell: `http://127.0.0.1:3000`
- API probes: `http://127.0.0.1:8000/healthz` and `/readyz`
- Mailpit: `http://127.0.0.1:8025`

PostgreSQL, Redis, and the mock VPN agent stay on an internal Docker network. The
agent container is read-only, drops every Linux capability, has no host mounts,
and exposes only health probes. It cannot provision a tunnel or execute commands.

Stop the stack with `make compose-down`. Local named volumes contain disposable
development data and must never be treated as backups.

## Quality gates

- Python: Ruff lint/format, strict mypy, pytest, and coverage thresholds for each
  service independently.
- Admin: Prettier, ESLint, strict TypeScript, Vitest, production Next.js build, and
  `npm audit` for production dependencies.
- Mobile: Dart format, Flutter analyze, and Flutter widget tests.
- Infrastructure: Compose model validation plus a build-and-health smoke test.
- Supply chain: dependency review, Dependabot, Gitleaks, and Trivy image scans.

GitHub Actions have read-only default permissions and third-party actions are
pinned to full commit SHAs. Production secrets must not be added to CI or local
Compose; use only documented placeholders until a deployment secret mechanism is
approved.
