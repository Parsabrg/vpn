# Project progress

Last updated: 2026-08-16

## Current phase

Phase 1.4 — account request, approval, and email workflow, implemented for review.
Phase 1.1 was squash-merged in pull request #2, Phase 1.2 in pull request #5, and
Phase 1.3 in pull request #10.

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
- Added neutral account-request submission with per-email/per-network rate limiting,
  a partial-unique-pending-email database guard for duplicate suppression, and
  append-only request-lifecycle events alongside the generic audit trail.
- Added row-locked (`SELECT ... FOR UPDATE`) admin approve/reject decisions that are
  idempotent under concurrent retries: an already-decided request returns its
  existing outcome instead of erroring, proven with a real-PostgreSQL concurrency
  test racing two sessions against the same request.
- Added activation-token issuance on approval (reusing the existing opaque-token/
  key-ring primitive under a new `activation` namespace) and single-use activation
  confirmation that sets the user's password and flips the account to active.
- Added a Redis-staged one-time email payload handoff (`nebula:email-outbox:v1:*`)
  so the durable `email_deliveries` outbox row never has to store a raw secret link,
  and a new standalone `services/worker` process that leases due deliveries with
  `SELECT ... FOR UPDATE SKIP LOCKED`, renders the four reviewed templates, sends
  through a stdlib-only SMTP or Resend adapter (no new runtime dependency), and
  retries with backoff before marking a delivery failed.
- Wired the worker into the Compose stack and CI (lint, type check, tests, Trivy
  image scan, Dependabot) alongside the API and VPN agent.

## Validation recorded locally

- API: Ruff, format, and strict mypy across 66 source/test files pass. The suite
  collects 346 tests and remains above the 95% branch-coverage gate (96.8%); two
  live PostgreSQL tests, the real-Redis atomicity test, and the new account-request
  concurrency test skip when those services are not configured locally and run in
  CI.
- Worker: Ruff, format, and strict mypy across 19 source/test files pass. The suite
  collects 49 tests and remains above the 95% branch-coverage gate (96.3%).
- VPN agent: Ruff, format, strict mypy, 7 pytest tests, and 96% branch coverage pass.
- Admin: Prettier, ESLint, strict TypeScript, 5 Vitest tests, and the production
  build pass; the image vulnerability scan remains a required CI gate.
- `compose.yaml` parses and the `worker` service is correctly wired to
  postgres/redis/mailpit health gates and the one-shot `migrate` job.
- All four Alembic revisions render successfully as offline PostgreSQL SQL, and
  static tests account for every one of the 27 model tables in both directions; no
  new migration was needed for Phase 1.4 (the schema was already in place).
- `pip check` reports no broken Python requirements; the current vulnerability
  audit remains a required CI gate.
- GitHub Action references use full commit SHAs.

The local machine did not have Flutter or a running Docker daemon. Flutter analysis,
widget tests, image builds, the container health smoke test, the real PostgreSQL
migration/permission round trip, and the new account-request concurrency test
therefore remain CI gates rather than locally verified claims.

## External inputs pending

- Repository visibility and source license.
- Minimum supported Android and Windows versions.
- Domain, administrator email, production email provider, VPS details, capacity,
  network ranges, and backup destination.
- Android and Windows tunnel verification devices or VMs.

## Next milestone

- Review and merge Phase 1.4 account request/approval/email workflow after all CI
  checks pass.
- Generate Android and Windows host projects after support versions are confirmed.
- Begin Phase 1.5 administrator dashboard (request queue, review actions, user and
  device management) in a separate pull request.

## Known limitations

- Account request, approval, activation, and outbox email delivery exist, but VPN
  provisioning, WireGuard/Xray runtime integration, native tunnel integration,
  administrator UI integration, backup, or production deployment does not exist yet.
- The worker's SMTP/Resend adapters are exercised against Mailpit and mocked
  transports; no production email provider credentials have been configured or
  verified end-to-end yet.
- `/readyz` proves API process state, database connectivity, exact schema version,
  and Redis connectivity; it is not proof of email, VPN-agent, or tunnel readiness,
  and the worker process has no readiness probe of its own (it is not an HTTP
  service).
- Python and Flutter direct dependencies are pinned, but their complete transitive
  graphs are not yet committed as platform-independent lock data.
- Authentication records carry key versions, but the current runtime file contract
  loads one active JWT/pepper/MFA version; non-disruptive multi-key rotation tooling
  remains production-operations work.
- Kill switch, DNS/IPv6 leak protection, and target-platform behavior remain
  unimplemented and unverified.
