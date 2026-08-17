# Phase 1 implementation plan

Phase 1 is split into reviewable vertical milestones. A milestone is complete only
when its implementation, tests, documentation, and security checks pass. Native VPN
features require target-platform verification; unit tests alone are insufficient.
Phase 1 ships native WireGuard, but every shared layer is built against the generic
protocol/profile model required by the final WireGuard plus Xray product. The Xray
delivery phases are defined in `protocol-roadmap.md`.

## Phase 0 — architecture baseline (complete)

Deliverables:

- Repository assessment
- Architecture and trust boundaries
- Threat model and privacy policy
- Environment/secret contract
- Owner decisions and credential checklist
- Progress record

Exit criteria: documentation is reviewed and merged; GitHub access is available.

## Phase 1.1 — monorepo and CI scaffold

Create the FastAPI, VPN agent, Next.js, and Flutter workspaces; pinned tool versions;
development Compose; local Mailpit; formatting/linting/test commands; and GitHub
Actions with minimal permissions, dependency review, Gitleaks, and container scans.

Checks:

- Python Ruff, mypy, pytest
- Next.js ESLint, TypeScript, unit test, production build
- Flutter format, analyze, unit test
- Compose configuration validation and container health smoke test
- Secret scan and dependency audit

## Phase 1.2 — database and identity foundation (complete)

Implement SQLAlchemy 2 models, enums, indexes, foreign keys, Alembic migrations,
PostgreSQL integration fixtures, and the interactive initial-admin seed command.
Create the identity, request, token, topology, protocol profile/capability,
assignment, credential, peer, audit, email, health, and settings tables described
in the architecture.

Checks include forward migration from empty DB, downgrade/upgrade where safe,
constraint tests, normalized identity uniqueness, and migration smoke tests.

## Phase 1.3 — authentication and administrator security (complete)

Implement Argon2id, user access/refresh flow, token-family rotation and reuse
detection, device sessions, logout/revocation, administrator password + TOTP MFA,
HttpOnly sessions, CSRF, rate limits, lockout, password reset, and audit events.

Adversarial tests cover enumeration, expired/reused tokens, session fixation, CSRF,
authorization boundaries, lockout bypass, and secret redaction.

## Phase 1.4 — request, approval, and email workflow (complete)

Implement neutral account requests, duplicate suppression, outbox delivery, SMTP and
Resend adapters, authenticated review, concurrent/idempotent approval, rejection,
activation, password creation, and delivery tracking.

The milestone must pass concurrent approval tests proving that exactly one user and
one active activation token result from retries.

Delivered as: account-request submission and admin approve/reject routes in
`services/api/src/nebula_api/accounts/`, reusing the Phase 1.2 schema unchanged; a
new standalone `services/worker` process that leases the `email_deliveries` outbox
with `SELECT ... FOR UPDATE SKIP LOCKED` and delivers through stdlib-only SMTP/Resend
adapters; and a Redis-staged one-time payload handoff so the outbox row itself never
retains a raw activation link or token, per the no-body/no-link constraint on
`EmailDelivery`. The concurrent-approval requirement is proven in
`services/api/tests/test_account_request_concurrency.py`, a real-PostgreSQL test
gated the same way as the existing live-database tests.

## Phase 1.5 — administrator dashboard (current)

Build the accessible responsive design system, login/MFA, overview, request queues,
review actions, users, device/session controls, permissions, assignments, health,
email status, and audit views. Destructive actions require confirmation and step-up
MFA where specified.

Protocol controls operate on reviewed capability IDs; administrators cannot create
raw Xray combinations or configuration fragments.

Component and API-contract tests cover loading, empty, error, forbidden, expired
session, keyboard, reduced-motion, and responsive states.

Delivered as: four new admin API packages behind reusable `require_admin_session`/
`authorize_admin_mutation` gates in `services/api/src/nebula_api/` --
`audit/` and `email_deliveries/` (read-only), `topology_admin/` (read-only,
deliberately empty until Phase 1.6 provisions anything), and `user_management/`
(list/detail plus disable/reactivate/device-revoke/session-revoke, step-up-MFA
gated and idempotent under concurrent retry, proven in
`test_user_management_concurrency.py`). The `apps/admin` Next.js app is now a real
session-gated dashboard rather than the Phase 1.1 placeholder: password/TOTP
sign-in, an overview, account-request review, filterable/paginated audit-log and
email-delivery tables, user management with a step-up TOTP retry flow for its
mutations, and honest empty-state shells for permissions/assignments/server-health
that name the Phase 1.6 dependency instead of faking data. Every admin mutation
maps onto the audit vocabulary already defined in
`services/api/src/nebula_api/models/operations.py`; permission-granting and
server-assignment mutation UI/API are intentionally out of scope until Phase 1.6
gives them something real to act on.

## Phase 1.6 — protocol-neutral VPN agent and WireGuard provisioning (complete)

Implement the versioned mTLS agent API, typed command validation, operation
idempotency, host hardening, address allocator, desired/actual state, atomic apply,
peer revoke, health, reconciliation, and partial-failure recovery. Provide a fake
WireGuard runner for CI and isolated Linux integration tests using network
namespaces where the runner permits it.

Define the protocol-driver interface and desired/actual provisioning state now.
Only the native WireGuard driver is enabled in Phase 1; the Xray driver is added in
the later milestone without changing the public control-plane contract.

No endpoint accepts shell text or arbitrary configuration fragments.

### Phase 1.6a / 1.6b split

Phase 1.6 shipped as two PRs along the natural agent/control-plane boundary.
**1.6a** (`services/vpn-agent` only) is complete: the typed agent API, the
`WireGuardDriver` protocol, `FakeWireGuardRunner`, `NativeWireGuardDriver`,
mTLS termination, host hardening (systemd unit, `services/vpn-agent/deploy/`),
and the gated CI network-namespace integration test. **1.6b**
(`services/api` only) is also complete: an mTLS `AgentClient`
(`agent_client/`, one instance per VPN server, classifying every failure
into `AgentUnreachable`/`AgentResponseAmbiguous`/`AgentRejected` so a lost
response is never mistaken for a definite outcome), the pure address
allocator (`provisioning/allocator.py`), `ProvisioningService`
(`provisioning/service.py`) running `request_peer`/`revoke_peer` as three
phases -- validate and write in-flight rows in one transaction, call the
agent outside any transaction, finalize in a fresh transaction -- proven
race-safe against real Postgres in `test_provisioning_concurrency.py`, the
first user-facing WireGuard API (`POST /v1/devices/{device_id}/wireguard-peer`
and its `/revoke` counterpart, gated by the new `require_user_session`
dependency), a one-shot reconciliation pass (`provisioning/reconciliation.py`,
run via the `reconcile-wireguard` CLI command) that recovers crashed
provision/revoke attempts and repairs safe drift without ever auto-repairing
an ambiguous result, and three CLI seed commands
(`seed-wireguard-protocol`, `create-vpn-server`, `grant-user-access`) for
bootstrapping topology data.

The exact contract 1.6b's agent client must honor, so it doesn't have to
re-derive this from `services/vpn-agent`'s source:

- Six typed operations, one route each, all `POST`:
  `/v1/operations/provision-device`, `/revoke-device`, `/enable-device`,
  `/disable-device`, `/health`, `/reconcile`. Request/response shapes are
  defined in `services/vpn-agent/src/nebula_agent/drivers/base.py`.
- Every mutating request (`provision_device`/`revoke_device`/`enable_device`/
  `disable_device`) requires `idempotency_key: UUID`, `correlation_id: UUID`,
  and `desired_generation: int`. A retried request with the same
  `idempotency_key` against the same `(operation_kind, target_id)` gets the
  agent's stored response replayed, not re-applied; against a *different*
  target it is rejected `409`. `health`/`reconcile` take no idempotency key
  (read-only, never ledgered).
- `applied_generation` in every mutation response echoes the request's
  `desired_generation` on success, or the target's last-successfully-applied
  generation on failure (`0` if it was never successfully applied) --
  callers should treat this as authoritative for updating
  `wireguard_peers.applied_generation`, not assume success implies the
  request's own `desired_generation` blindly (it does, but the field is
  there so a failure path is equally unambiguous).
- `ProvisionDeviceResponse` carries every field a client profile needs
  (`server_public_key`, `listen_port`, `public_endpoint`, `client_dns`,
  `client_allowed_ips`, `persistent_keepalive_seconds`) -- there is no
  separate `get_client_profile` operation.
- The connection must present a client certificate; the agent's own
  `ssl_cert_reqs=CERT_REQUIRED` listener rejects the TLS handshake
  otherwise. There is no additional bearer-token or header-based auth layer
  on top of mTLS.
- `reconcile`'s `outcome` is only ever `in_sync`, `drift_detected`, or
  `ambiguous` from the agent -- `repair_requested`/`repair_succeeded`/
  `repair_failed` are 1.6b's own reconciliation-job vocabulary, produced
  after deciding what to do about a `drift_detected`/`ambiguous` result, not
  something the agent itself reports.
- The agent validates that `assigned_address` falls inside its own
  configured `wg_client_pool`; 1.6b's address allocator must never hand out
  an address that isn't actually inside the target server's pool, or every
  `provision_device`/`enable_device` call for that peer will fail.

## Phase 1.7 — Flutter foundation and account lifecycle

Build Material 3 tokens, light/dark/system themes, Riverpod state, GoRouter routes,
Dio client, secure token storage, splash, sign-in, request, activation, home shell,
account, devices, settings, diagnostics, logs, and all connection states.

The server/profile picker is capability-driven. In Phase 1 it displays WireGuard;
later it displays only the Xray profiles enabled for that server and user without a
client update for every new profile record.

Flutter tests cover state transitions, token refresh serialization, revocation,
offline behavior, accessibility labels, and reduced motion.

## Phase 1.8 — Android WireGuard integration

Use Android `VpnService` and a maintained WireGuard-compatible native tunnel
library through a small platform boundary. Generate the client key locally, keep it
in Keystore-backed storage, register only the public key, and implement connect,
disconnect, network change, recovery, and best-supported leak safeguards.

Verify on at least one current physical Android device and one supported emulator
or second device profile. Record OS/vendor limitations. Do not mark kill switch,
DNS, or IPv6 leak protection complete without packet-level tests.

## Phase 1.9 — Windows WireGuard integration

Use the official WireGuard for Windows embeddable/tunnel-service approach where its
license and distribution terms fit. Store key material with DPAPI or Credential
Manager, keep the UI process unprivileged where possible, and isolate elevation in
the smallest signed helper/service boundary.

Verify install, connect, disconnect, upgrade, uninstall, sleep/resume, network
change, non-admin behavior, and leak controls on supported Windows versions.

## Phase 1.10 — production operations

Add hardened production images and Compose, Nginx/TLS, systemd unit, firewall/NAT,
health probes, metrics without traffic metadata, log rotation, encrypted off-host
backup/restore, upgrade/rollback, and clean-Ubuntu deployment runbooks.

Deployment is manual until credentials and explicit production permission exist.

## Phase 1.11 — end-to-end acceptance

Run the complete lifecycle:

1. Submit account request.
2. Deliver administrator notification.
3. Sign in as administrator with MFA.
4. Approve concurrently/repeatedly and create exactly one user.
5. Deliver and consume one activation link.
6. Set password and sign in from Flutter.
7. Register a device public key and provision one peer.
8. Connect and validate expected tunnel/DNS behavior.
9. Revoke access and confirm app sessions and WireGuard peer stop working.
10. Restore a backup into a clean environment.
11. Pass CI, dependency, secret, and container checks.
12. Verify that disabled/unimplemented Xray profiles cannot be selected or
    provisioned and that the generic driver contract rejects raw configuration.

## Definition of done

The original 15 acceptance criteria remain authoritative. In addition, every claim
must cite a passing automated check or a recorded target-platform verification.
Known limitations must be visible in the UI and operations documentation.
The final multi-protocol product is not complete when Phase 1 ends; Xray milestones
have their own acceptance gates in `protocol-roadmap.md`.
