# Project progress

Last updated: 2026-08-17

## Current phase

Phase 1.6a — VPN agent (typed API, native WireGuard driver, host hardening),
implemented for review. Phase 1.1 was squash-merged in pull request #2,
Phase 1.2 in pull request #5, Phase 1.3 in pull request #10, Phase 1.4 in
pull request #24, and Phase 1.5 in pull request #28. Phase 1.6 is split into
1.6a (this pass: `services/vpn-agent` only) and a follow-on 1.6b
(`services/api`: agent client, provisioning orchestration, address allocator,
reconciliation job, CLI seeding) along the natural agent/control-plane
boundary.

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
- Added four new read/write API packages behind reusable admin-session and
  step-up-MFA authorization gates: append-only audit-log and email-delivery
  read endpoints, a read-only topology package (protocols, protocol profiles,
  VPN servers) that stays deliberately empty until Phase 1.6 provisions
  anything, and a user-management package (list/detail, disable/reactivate,
  device/session revocation) whose mutations are idempotent under concurrent
  retry, proven with a new real-PostgreSQL concurrency test.
- Replaced the Phase 1.1 admin placeholder pages with a real, session-gated
  Next.js dashboard: password/TOTP sign-in, an overview composed from the
  existing list endpoints, account-request review, filterable/paginated audit
  log and email-delivery tables, user management with device/session revocation
  behind a step-up TOTP retry flow, and honest empty-state shells for
  permissions/assignments/server health that explain the Phase 1.6 dependency
  instead of faking data.
- Added the CSS this phase's markup needed (buttons, fields, badges, data
  tables with a card breakpoint, dialogs, pagination) and test coverage across
  loading, empty, error, forbidden, expired-session, keyboard, reduced-motion,
  and responsive states.
- Replaced the Phase 1.1 VPN-agent probe-only scaffold with a typed
  `/v1/operations/{provision,revoke,enable,disable}-device`, `/health`,
  `/reconcile` API, a `WireGuardDriver` protocol with two implementations
  (an in-memory `FakeWireGuardRunner` used everywhere except real
  deployment, and a `NativeWireGuardDriver` driving real `wg`/`wg-quick`
  subprocess calls -- fixed argv only, never a shell), atomic apply with
  rollback to a last-known-good on-disk config, and a local idempotency
  ledger so retried requests replay instead of re-applying.
- Added mTLS termination directly in uvicorn (`nebula_agent.serve`), a
  hardened systemd unit implementing every threat-model "agent hardening"
  checklist line, and a CI job that creates a real (namespaced) kernel
  WireGuard interface to exercise the native driver end to end -- separate
  from the containerized `checks` job since it needs real `CAP_NET_ADMIN`.
  The Compose `vpn-agent:` service still only ever runs the capability-free
  fake driver, unchanged from Phase 1.1's "no network-administration
  capability" scaffold design.

## Validation recorded locally

- API: Ruff, format, and strict mypy pass. The suite collects 404 tests (5 skip
  locally) and remains above the 95% branch-coverage gate (96.6%); the live
  PostgreSQL tests, the real-Redis atomicity test, and the account-request and
  user-management concurrency tests skip when those services are not configured
  locally and run in CI.
- Worker: Ruff, format, and strict mypy across 19 source/test files pass. The suite
  collects 49 tests and remains above the 95% branch-coverage gate (96.3%).
- VPN agent: Ruff, format, strict mypy, 122 pytest tests, and 98% branch
  coverage pass. `NativeWireGuardDriver`'s subprocess calls are exercised
  through a mocked `run_fixed_argv` boundary locally; the one real-kernel
  netns integration test is gated (`NEBULA_WG_NETNS_INTEGRATION`) and skips
  locally, same shape as the Postgres-gated API tests -- there is no root
  access, WireGuard kernel module, or `wg`/`wg-quick` tooling on this
  Windows development machine to run it directly.
- Admin: Prettier, ESLint, strict TypeScript, 32 Vitest tests, and the production
  build pass with `NEBULA_API_INTERNAL_URL`/`NEBULA_ADMIN_ORIGIN` set (now required
  at build time so Next's static/dynamic bailout can reach the `cookies()` call
  every protected route depends on); the image vulnerability scan remains a
  required CI gate.
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
therefore remain CI gates rather than locally verified claims. The same is true of
the new `netns-integration` CI job: whether a GitHub-hosted `ubuntu-latest` runner's
kernel actually supports creating a WireGuard interface is unverified from here --
the job is written to warn and skip gracefully rather than fail if it doesn't,
pending a few real CI runs to confirm reliability before tightening that to fail-loud.

## External inputs pending

- Repository visibility and source license.
- Minimum supported Android and Windows versions.
- Domain, administrator email, production email provider, VPS details, capacity,
  network ranges, and backup destination.
- Android and Windows tunnel verification devices or VMs.

## Next milestone

- Review and merge the Phase 1.6a VPN agent after all CI checks pass,
  including confirming the new `netns-integration` job actually runs its
  real assertions (not just the warn-and-skip fallback) on GitHub-hosted
  runners.
- Begin Phase 1.6b: the `services/api` side of provisioning -- an mTLS
  agent client, orchestration against `agent_operations`, the address
  allocator, the reconciliation job, and a CLI seed command (matching
  `seed_admin.py`'s pattern) for creating VPN servers and granting
  permissions, since there is still no way to create a `vpn_servers` row
  without raw SQL.
- Generate Android and Windows host projects after support versions are
  confirmed.

## Known limitations

- Account request, approval, activation, outbox email delivery, and an
  administrator dashboard to review and act on all of it now exist. The VPN
  agent can now provision/revoke/enable/disable a real WireGuard peer and
  report health/reconciliation against a real interface, but nothing on the
  control-plane side calls it yet -- there is no agent client, no
  provisioning orchestration, no address allocator, and no reconciliation
  job (all Phase 1.6b). Xray runtime integration, native client tunnel
  integration, backup, and production deployment do not exist yet either.
- There is still no way to create a `vpn_servers` row, grant a protocol
  permission, or assign a user to a server without raw SQL -- Phase 1.6b
  adds a CLI seed command for this, by design rather than new admin
  dashboard mutation UI this round.
- The administrator dashboard's permissions, assignments, and server-health pages
  are honest empty-state shells: no VPN server or protocol profile has ever been
  created, and permissions/assignments have no backend API at all yet, both by
  design until Phase 1.6b.
- The VPN agent's real driver is only exercised by the gated CI netns job and
  (once deployed) the systemd unit in `services/vpn-agent/deploy/` -- it never
  runs in this repository's Docker/Compose stack, which stays on the
  capability-free fake driver by design.
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
