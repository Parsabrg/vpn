# Project progress

Last updated: 2026-07-26

## Current phase

Phase 1.3 — authentication and administrator security, implemented for review.
Phase 1.1 was squash-merged in pull request #2 and Phase 1.2 in pull request #5.

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
- Added 27 explicit PostgreSQL tables for identity, approval, tokens, reviewed
  protocol topology, provisioning intent, audit, delivery, health, and settings.
- Added four linear, immutable Alembic revisions with an exact runtime schema-head
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
- Added separate user bearer-token and administrator cookie/MFA realms. User login
  issues strict Ed25519 access JWTs and rotating opaque refresh tokens; every
  protected request reloads the PostgreSQL user, device, and session for immediate
  revocation.
- Added one-active-session-per-device and one-active-refresh-per-session database
  invariants, fixed refresh-family expiry, atomic rotation, reuse detection, and
  family revocation under row locks.
- Added neutral password-reset request/confirmation, keyed single-use token digests,
  rate limits before expensive password hashing, and revocation of all existing
  user sessions after password replacement. Reliable email delivery remains the
  Phase 1.4 boundary.
- Added administrator password challenges, first-time TOTP enrollment, encrypted
  TOTP seeds, durable replay counters, single-use recovery codes, short-lived Redis
  sessions, fresh step-up sessions, exact-origin checks, rotating CSRF tokens,
  lockout, and dual keyed-account/network rate limits.
- Added fail-closed Redis Lua transitions, production key-file validation, generic
  public errors, no-store/referrer controls, redacted validation responses, and an
  expanded append-only authentication audit vocabulary.

## Validation recorded locally

- API: Ruff, format, and strict mypy across 58 source/test files pass. The suite
  collects 303 tests and remains above the 95% branch-coverage gate; two live
  PostgreSQL tests and the real-Redis atomicity test skip when those services are
  not configured locally and run in CI.
- VPN agent: Ruff, format, strict mypy, 7 pytest tests, and 96% branch coverage pass.
- Admin: Prettier, ESLint, strict TypeScript, 5 Vitest tests, and the production
  build pass; the image vulnerability scan remains a required CI gate.
- Compose configuration renders successfully.
- All four Alembic revisions render successfully as offline PostgreSQL SQL, and
  static tests account for every one of the 27 model tables in both directions.
- `pip check` reports no broken Python requirements; the current vulnerability
  audit remains a required CI gate.
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

- Review and merge Phase 1.3 authentication/security after all CI checks pass.
- Generate Android and Windows host projects after support versions are confirmed.
- Begin Phase 1.4 account request, approval, and reliable email delivery in a
  separate pull request.

## Known limitations

- Authentication endpoints exist, but no password-reset delivery adapter, account
  approval behavior, reliable email worker, administrator UI integration, VPN
  provisioning, WireGuard/Xray runtime integration, native tunnel integration,
  backup, or production deployment exists yet.
- `/readyz` proves API process state, database connectivity, exact schema version,
  and Redis connectivity; it is not proof of email, VPN-agent, or tunnel readiness.
- Python and Flutter direct dependencies are pinned, but their complete transitive
  graphs are not yet committed as platform-independent lock data.
- Authentication records carry key versions, but the current runtime file contract
  loads one active JWT/pepper/MFA version; non-disruptive multi-key rotation tooling
  remains production-operations work.
- Kill switch, DNS/IPv6 leak protection, and target-platform behavior remain
  unimplemented and unverified.
