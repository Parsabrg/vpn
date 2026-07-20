# Project progress

Last updated: 2026-07-20

## Current phase

Phase 1.2 — database and identity foundation, implemented for review. Phase 0 was
squash-merged in pull request #1 and Phase 1.1 in pull request #2.

## Completed

- Defined and merged the multi-protocol architecture, threat model, environment
  contract, and delivery roadmap.
- Created independent FastAPI control-plane and VPN-agent packages with immutable,
  validated settings and non-sensitive health/readiness probes.
- Kept the API unprivileged and restricted the agent scaffold to two probe routes;
  it accepts no shell text, protocol configuration, or provisioning operation.
- Added non-root Python container images and an accessible, responsive Next.js
  administration shell that explicitly labels unimplemented capabilities.
- Added a Flutter 3.44 shared client shell and widget test without claiming native
  tunnel support.
- Added a loopback-only development Compose stack with PostgreSQL, persistent Redis,
  Mailpit, isolated networks, health gates, read-only application containers, and
  a capability-free mock agent.
- Added minimal-permission CI for Python, Next.js, Flutter, Compose smoke testing,
  dependency review, secret scanning, and container vulnerability scanning.
- Added exact tool/direct-dependency pins, an npm lockfile, Dependabot, root task
  commands, and a development guide.
- Added 25 explicit PostgreSQL tables for identity, approval, tokens, reviewed
  protocol topology, provisioning intent, audit, delivery, health, and settings.
- Added three linear, immutable Alembic revisions with an exact runtime schema-head
  check; application startup never runs migrations.
- Added separate configurable login roles for application DML and migrations. A
  fixed inherited runtime group cannot perform DDL, mutate the Alembic version, or
  update/delete append-only audit rows.
- Added deterministic email/username normalization, fixed-length token-digest and
  envelope-encryption constraints, protocol-profile versioning, restrictive foreign
  keys, and cross-table credential identity constraints.
- Added an interactive, advisory-lock-protected initial-owner command using Argon2id.
  It accepts passwords only through hidden confirmation prompts and writes its audit
  event in the same transaction.
- Changed `/readyz` to require PostgreSQL connectivity and the exact checked-in
  migration head while retaining generic, non-sensitive probe responses.
- Added a one-shot Compose migration service and PostgreSQL CI coverage for an
  empty-database upgrade, metadata drift, application-role DDL denial, audit
  append-only enforcement, and migration-version protection.

## Validation recorded locally

- API: Ruff, format, strict mypy across 32 source files, 100 pytest tests, and 98.09%
  branch coverage pass; one live-PostgreSQL permission test is skipped locally.
- VPN agent: Ruff, format, strict mypy, 7 pytest tests, and 96% branch coverage pass.
- Admin: Prettier, ESLint, strict TypeScript, 5 Vitest tests, production build, and
  production dependency audit pass.
- Compose configuration renders successfully.
- All three Alembic revisions render successfully as offline PostgreSQL SQL, and
  static tests account for every one of the 25 model tables in both directions.
- The installed Python dependency graph reports no known vulnerabilities; the two
  local editable workspace packages are correctly not found on PyPI.
- GitHub Action references use full commit SHAs.

The local machine did not have Flutter or a running Docker daemon. Flutter analysis,
widget tests, image builds, the container health smoke test, and the real PostgreSQL
migration/permission round trip therefore remain CI gates rather than locally
verified claims.

## External inputs pending

- Repository visibility and source license.
- Minimum supported Android and Windows versions.
- Domain, administrator email, production email provider, VPS details, capacity,
  network ranges, and backup destination.
- Android and Windows tunnel verification devices or VMs.

## Next milestone

- Review and merge the Phase 1.2 database foundation after all CI checks pass.
- Generate Android and Windows host projects after support versions are confirmed.
- Begin Phase 1.3 authentication and administrator security in a separate pull
  request.

## Known limitations

- The schema exists, but no authentication endpoint, account approval behavior,
  email delivery, VPN provisioning, WireGuard/Xray runtime integration, native
  tunnel integration, backup, or production deployment exists yet.
- `/readyz` proves only API process state, database connectivity, and schema version;
  it is not proof of Redis, email, VPN-agent, or tunnel readiness.
- Python and Flutter direct dependencies are pinned, but their complete transitive
  graphs are not yet committed as platform-independent lock data.
- Kill switch, DNS/IPv6 leak protection, and target-platform behavior remain
  unimplemented and unverified.
