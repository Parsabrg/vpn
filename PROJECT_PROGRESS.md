# Project progress

Last updated: 2026-08-21

## Current phase

Phase 1.7b — device connection (`apps/mobile`: a real devices screen
replacing Phase 1.7a's placeholder, calling the new
`GET /v1/servers/` endpoint to let a user pick a server/profile, generating
a WireGuard identity on-device, and calling the existing
`POST /v1/devices/{id}/wireguard-peer` (request/revoke) API), implemented
for review on top of the not-yet-merged Phase 1.7a branch. Phase 1.1 was
squash-merged in pull request #2, Phase 1.2 in pull request #5, Phase 1.3 in
pull request #10, Phase 1.4 in pull request #24, Phase 1.5 in pull request
#28, Phase 1.6a (`services/vpn-agent`) in pull request #30, and Phase 1.6b
(control-plane VPN provisioning) in pull request #31. Phase 1.7a (Flutter
foundation and account lifecycle) is implemented for review in pull request
#38; this phase's API half (the new `GET /v1/servers/` endpoint) is
implemented for review in pull request #39. Phase 1.7b's mobile half
(this entry) depends on both and is branched from Phase 1.7a's branch
rather than `main`, since it needs 1.7a's routing/state/screens that
haven't merged yet.

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
- Closed the Phase 1.6 control-plane gap: an mTLS `AgentClient` (one
  instance per VPN server, classifying every agent-call failure into
  unreachable/response-ambiguous/rejected so a lost response is never
  mistaken for a definite outcome), a pure address allocator, and
  `ProvisioningService` running peer request/revoke as three phases --
  validate and write in-flight rows in one transaction, call the agent
  outside any transaction, finalize in a fresh transaction -- proven
  race-safe against real PostgreSQL in a new concurrency test.
- Added the first user-facing WireGuard API: `POST
  /v1/devices/{device_id}/wireguard-peer` and its `/revoke` counterpart,
  gated by a new `require_user_session` bearer-token dependency (extracted
  from the existing `/v1/auth/me` handler) with the same generic-denial
  posture as every other route in this codebase.
- Added a one-shot reconciliation pass (`reconcile-wireguard` CLI command)
  that compares each in-flight or steady-state peer against the agent's
  observed state, recovers DB state after a crash between the agent call
  and its own follow-up transaction, repairs safe drift by re-issuing the
  appropriate operation, and records (never auto-repairs) ambiguous drift
  for operator triage, exiting non-zero on any repair failure or ambiguity.
- Added three CLI seed commands (`seed-wireguard-protocol`,
  `create-vpn-server`, `grant-user-access`), matching `seed_admin.py`'s
  advisory-lock/transaction/audit shape -- there is now a way to create a
  `vpn_servers` row and grant protocol permissions without raw SQL.
- Replaced the Phase 1.1 `apps/mobile` placeholder shell with a real,
  themed, routed, stateful Flutter app: Material 3 light/dark/system
  theming with a single reduced-motion enforcement point used by every page
  transition; hand-written Riverpod state (no codegen, to keep the existing
  `pub get -> format -> analyze -> test` CI pipeline unchanged); a GoRouter
  route table with a single `redirect` driven by a closed `AuthState` sum
  type (`AuthAuthenticating` / `AuthUnauthenticated` / `AuthAuthenticated` /
  `AuthSessionExpired`); and a Dio client whose `AuthInterceptor` attaches
  bearer tokens and, on a 401, serializes concurrent token refreshes behind
  a single in-flight `Completer` (`TokenRefresher`) so N simultaneous
  expired-token requests trigger exactly one `/v1/auth/refresh` call.
- Added `SecureTokenStore` (refresh token only, Keystore/DPAPI-backed via
  `flutter_secure_storage`; the short-lived access token stays in memory)
  and plain `shared_preferences`-backed stores for the non-secret
  server-assigned `device_id` and the theme-mode override -- both kept
  behind narrow interfaces so tests substitute in-memory fakes instead of
  hitting platform channels unavailable in headless `flutter test`.
- Added the account-lifecycle screens against the real, already-shipped
  endpoints: splash (silent refresh-token bootstrap), sign-in, account
  request, activation, and password reset (request + confirm) -- request/
  reset screens render identical neutral copy regardless of outcome,
  matching the API's own account-enumeration-resistant design, and
  activation/reset tokens are entered by manual paste (no deep-linking
  infrastructure this phase). Device name/platform/client-version are
  sourced from `dart:io`/a manually-synced constant rather than adding
  `device_info_plus`/`package_info_plus`, matching this repo's
  minimal-dependency discipline.
- Added an authenticated home shell (bottom-nav Devices/Account/Settings):
  Account renders `/v1/auth/me` and signs out (clearing local state
  unconditionally, even if the network logout call fails); Settings holds
  the theme-mode control; Devices is an honest empty state naming the
  Phase 1.7b server-discovery dependency instead of faking a device list,
  mirroring `apps/admin`'s Phase 1.5 empty-state precedent.
- Added a new `services/api` endpoint, `GET /v1/servers/`
  (`nebula_api/servers/`), bearer-token gated: joins
  `user_server_assignments -> vpn_servers -> server_protocol_capabilities ->
  protocol_profiles -> user_protocol_permissions` scoped to the caller's own
  `user_id`, returning a server/profile only when every one of those rows is
  active/enabled/unexpired. This is what Phase 1.7a's Flutter devices
  placeholder was waiting on. Proven correct against real PostgreSQL (per-user
  isolation, a disabled permission hiding an otherwise-eligible server) --
  the fixture setup hit two real schema constraints (a closed,
  singleton-paired `protocols.code` vocabulary; a nulls-not-distinct unique
  constraint on `protocol_profiles`) only CI's real Postgres could catch,
  since this development machine has none.
- Replaced `apps/mobile`'s Phase 1.7a devices placeholder with a real
  screen: loads `GET /v1/servers/`, lets the user pick a server and
  protocol profile, generates a Curve25519 WireGuard identity on-device
  (`package:cryptography`'s pure-Dart X25519 -- no native platform code,
  keeping this app Dart-only) persisted in secure storage and reused across
  connect attempts, and calls the existing
  `POST /v1/devices/{id}/wireguard-peer` (request) and `.../revoke` API.
  The "connected" view is explicit that provisioning a peer registers the
  device with the server but does not establish a live tunnel -- that needs
  native platform integration this app doesn't have yet -- rather than
  implying a working VPN connection that doesn't exist.

## Validation recorded locally

- API: Ruff, format, and strict mypy pass. The suite collects 539 tests (7 skip
  locally) and remains above the 95% branch-coverage gate (96.0%); the live
  PostgreSQL tests (including the two new provisioning-concurrency tests), the
  real-Redis atomicity test, and the account-request/user-management
  concurrency tests skip when those services are not configured locally and
  run in CI.
- Worker: Ruff, format, and strict mypy across 19 source/test files pass. The suite
  collects 54 tests and remains above the 95% branch-coverage gate (96.5%),
  with `poller.py` at 100% after the lease-reclamation work.
- VPN agent: Ruff, format, strict mypy, 126 pytest tests, and 98% branch
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
- Mobile: `flutter pub get`, `dart format --set-exit-if-changed`,
  `flutter analyze --fatal-infos`, and `flutter test` (30 tests across
  `AuthNotifier` state transitions, `TokenRefresher` concurrency, Dio error
  translation, GoRouter redirect behavior, reduced motion, and screen-level
  form/accessibility checks) all pass, confirmed both locally (Flutter 3.44.9,
  bootstrapped via the community mirrors at `storage.flutter-io.cn` /
  `pub.flutter-io.cn` after `storage.googleapis.com`/`pub.dev` proved
  intermittently blocked from this development machine) and by the PR's own
  `Flutter / checks` GitHub Actions job (`ghcr.io/cirruslabs/flutter:3.44.0`)
  on pull request #38. Three real defects surfaced only by running these
  tools -- not caught by manual review -- and were fixed: two test files
  used `secureTokenStoreProvider`/`deviceIdStoreProvider` without importing
  `storage_providers.dart`; `AccountScreen` called `const Semantics(...)`
  though `Semantics`'s constructor isn't const in this Flutter version; and
  two tests had incorrect setup (a login-failure test skipped driving the
  notifier to `Unauthenticated` first, and a splash-screen router test used
  `pumpAndSettle` against a screen whose progress indicator animates
  indefinitely and therefore never settles).
- The PR's `Dependency review` check fails on a Dart-ecosystem license-casing
  quirk, not a real license problem: pub.dev reports licenses lowercased
  (e.g. `bsd-3-clause`), which the action's case-sensitive SPDX matching
  can't validate, so it reports "could not detect the validity" for every
  new package even though direct inspection of each package's cached
  `LICENSE` file confirms they are all MIT, Apache-2.0, or BSD-3-Clause --
  nowhere near the `deny-licenses` list. Left as a known CI false positive
  rather than switching `dependency-review.yml` from `deny-licenses` to
  `allow-licenses` (they are mutually exclusive in
  `actions/dependency-review-action`, and switching would need auditing
  every ecosystem in this repo -- npm, pip, GitHub Actions -- not just the
  new Dart packages, which is out of scope for a Flutter-only phase).
- Phase 1.7b's API half (`GET /v1/servers/`, pull request #39): Ruff,
  format, and strict mypy pass; 7 new unit/route tests pass locally and 2
  new real-Postgres integration tests (gated on `NEBULA_DATABASE_URL`, not
  configured on this machine -- Docker Desktop and a native PostgreSQL 17
  install both failed to start here, no admin/UAC elevation available in
  this sandbox) skip cleanly locally and are confirmed passing by the PR's
  own CI. Their first version had two real schema-constraint bugs (see
  "Completed" above) that only that CI run caught.
- Phase 1.7b's mobile half (devices screen): `dart format`, `flutter
  analyze --fatal-infos`, and `flutter test` (44 tests, +14 over Phase
  1.7a's 30: WireGuard key-pair generation/reconstruction against the
  real `package:cryptography` X25519 implementation, `DevicesController`
  load/connect/disconnect state transitions, and devices-screen empty/
  picker/connected rendering) all pass locally with the same bootstrapped
  Flutter 3.44.9 toolchain used for Phase 1.7a. Not yet confirmed by this
  branch's own CI run (no PR opened yet as of this entry) -- flagging that
  distinction rather than claiming a CI result that doesn't exist yet.
- GitHub Action references use full commit SHAs.

The local machine did not have Flutter or a running Docker daemon. Flutter analysis,
widget tests, image builds, the container health smoke test, the real PostgreSQL
migration/permission round trip, and the concurrency tests therefore remain CI gates
rather than locally verified claims.

The `netns-integration` job's open question is now resolved: on GitHub-hosted
`ubuntu-latest` runners it creates a real kernel WireGuard interface and runs its
real assertion (`1 passed`), not the warn-and-skip fallback -- confirmed from the
job log on PR #31. The graceful-skip branch remains in place as a guard against
future runner-image changes; tightening it to fail-loud is a deliberate follow-up
rather than something to change while it is providing real coverage.

## External inputs pending

- Repository visibility and source license.
- Minimum supported Android and Windows versions.
- Domain, administrator email, production email provider, VPS details, capacity,
  network ranges, and backup destination.
- Android and Windows tunnel verification devices or VMs.

## Next milestone

- Review and merge Phase 1.7a (pull request #38) and Phase 1.7b's API half
  (pull request #39), then rebase/merge Phase 1.7b's mobile half (devices
  screen) onto `main` once both land -- it is currently branched from
  Phase 1.7a's branch, not `main`, since it depends on routing/state/
  screens that haven't merged yet.
- No CLI seed data exists yet for `user_server_assignments`/
  `user_protocol_permissions`, so `GET /v1/servers/` has nothing to return
  for any real user today -- the devices screen's "no servers assigned"
  empty state is what every account will actually see until an
  administrator grants an assignment via the existing
  `grant-user-access`/`create-vpn-server` CLI seed commands. Worth a
  documented manual verification pass (seed a server + assignment,
  confirm the picker/connect/disconnect flow end to end) once a real VPS
  and Postgres are available, since this development machine has neither.
- Generate Android and Windows host projects after support versions are
  confirmed -- that unblocks real native WireGuard tunnel establishment,
  which the devices screen's "peer provisioned, not yet tunneling" wording
  is deliberately honest about not having yet.

## Known limitations

- Account request, approval, activation, outbox email delivery, an
  administrator dashboard, and now a complete WireGuard provisioning path
  (mTLS agent client, three-phase orchestration, address allocation,
  reconciliation, and a user-facing peer-request API) all exist. Xray
  runtime integration, native client tunnel integration, backup, and
  production deployment do not exist yet.
- The Flutter app now calls the full WireGuard provisioning path (server
  discovery, peer request, peer revoke), but provisioning a peer only
  registers the device with the server -- it does not establish a live
  tunnel. That needs native Android/Windows platform integration (a TUN
  interface, `wg`/`wg-quick` or equivalent), which this app does not have
  yet since it has no native runner projects at all (see "Next milestone").
  The devices screen says this explicitly rather than implying a working
  VPN connection.
- No `user_server_assignments`/`user_protocol_permissions` rows exist for
  any real user yet -- only the CLI seed commands below can create them, and
  none have been run against a real deployment. Every account will see the
  devices screen's "no servers assigned yet" empty state until that
  changes.
- Creating a `vpn_servers` row, seeding the WireGuard protocol/profile, and
  granting permissions/assignments is done via CLI seed commands
  (`nebula-api seed-wireguard-protocol|create-vpn-server|grant-user-access`),
  by design rather than new admin dashboard mutation UI this round.
- The administrator dashboard's permissions, assignments, and server-health
  pages remain honest empty-state shells: Phase 1.6b added CLI seeding and a
  user-facing provisioning API, not new admin dashboard mutation UI for
  granting permissions/assignments or viewing server health -- that stays
  out of scope until a later phase revisits the admin dashboard.
- WireGuard client-address allocation never reclaims addresses from
  revoked/failed peers (`wireguard_peers`' server+address uniqueness
  constraint is unconditional, not scoped to live peers) -- an address pool
  must be sized generously for its expected device churn. Accepted as a
  Phase 1 limitation rather than a live schema change.
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
