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

## Phase 1.1 — monorepo and CI scaffold (current)

Create the FastAPI, VPN agent, Next.js, and Flutter workspaces; pinned tool versions;
development Compose; local Mailpit; formatting/linting/test commands; and GitHub
Actions with minimal permissions, dependency review, Gitleaks, and container scans.

Checks:

- Python Ruff, mypy, pytest
- Next.js ESLint, TypeScript, unit test, production build
- Flutter format, analyze, unit test
- Compose configuration validation and container health smoke test
- Secret scan and dependency audit

## Phase 1.2 — database and identity foundation

Implement SQLAlchemy 2 models, enums, indexes, foreign keys, Alembic migrations,
PostgreSQL integration fixtures, and the interactive initial-admin seed command.
Create the identity, request, token, topology, protocol profile/capability,
assignment, credential, peer, audit, email, health, and settings tables described
in the architecture.

Checks include forward migration from empty DB, downgrade/upgrade where safe,
constraint tests, normalized identity uniqueness, and migration smoke tests.

## Phase 1.3 — authentication and administrator security

Implement Argon2id, user access/refresh flow, token-family rotation and reuse
detection, device sessions, logout/revocation, administrator password + TOTP MFA,
HttpOnly sessions, CSRF, rate limits, lockout, password reset, and audit events.

Adversarial tests cover enumeration, expired/reused tokens, session fixation, CSRF,
authorization boundaries, lockout bypass, and secret redaction.

## Phase 1.4 — request, approval, and email workflow

Implement neutral account requests, duplicate suppression, outbox delivery, SMTP and
Resend adapters, authenticated review, concurrent/idempotent approval, rejection,
activation, password creation, and delivery tracking.

The milestone must pass concurrent approval tests proving that exactly one user and
one active activation token result from retries.

## Phase 1.5 — administrator dashboard

Build the accessible responsive design system, login/MFA, overview, request queues,
review actions, users, device/session controls, permissions, assignments, health,
email status, and audit views. Destructive actions require confirmation and step-up
MFA where specified.

Protocol controls operate on reviewed capability IDs; administrators cannot create
raw Xray combinations or configuration fragments.

Component and API-contract tests cover loading, empty, error, forbidden, expired
session, keyboard, reduced-motion, and responsive states.

## Phase 1.6 — protocol-neutral VPN agent and WireGuard provisioning

Implement the versioned mTLS agent API, typed command validation, operation
idempotency, host hardening, address allocator, desired/actual state, atomic apply,
peer revoke, health, reconciliation, and partial-failure recovery. Provide a fake
WireGuard runner for CI and isolated Linux integration tests using network
namespaces where the runner permits it.

Define the protocol-driver interface and desired/actual provisioning state now.
Only the native WireGuard driver is enabled in Phase 1; the Xray driver is added in
the later milestone without changing the public control-plane contract.

No endpoint accepts shell text or arbitrary configuration fragments.

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
