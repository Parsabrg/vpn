# Threat model

## Scope and security objectives

This model covers the Phase 1 control plane, administrator dashboard, background
worker, PostgreSQL, Redis, email links, VPN agent, native WireGuard, Xray-core,
Android and Windows clients, CI, deployment, and backups.

Primary objectives:

- Only approved, active users and registered devices receive VPN access.
- Account approval and revocation are authenticated, authorized, auditable, and
  idempotent.
- Passwords, tokens, MFA seeds, client private keys, server private keys, and
  infrastructure credentials do not leak.
- Compromise of the public API does not automatically grant root shell access.
- Revocation converges across application sessions, WireGuard peers, and Xray
  credentials/configuration.
- Operational logs do not become a browsing or traffic-surveillance dataset.

## Assets

- User and administrator identities
- Password hashes, token hashes, MFA seeds, and recovery-code hashes
- Client and server WireGuard key material
- Xray UUIDs/passwords, client profiles, TLS/REALITY keys, and trusted templates
- VPN server configuration and allocated addresses
- Approval, assignment, expiration, and device-limit state
- Audit evidence and email-delivery state
- Database and encrypted backups
- CI/CD identities, container images, and release artifacts

## Adversaries

- Unauthenticated internet attacker
- Credential-stuffing attacker with reused passwords
- Malicious or compromised approved user
- Compromised user device
- Compromised administrator browser or mailbox
- Malicious insider with limited operational access
- Supply-chain attacker targeting dependencies, actions, or images
- Attacker who compromises the public API container
- Attacker with network position between internal services

## Major threats and controls

| Threat                 | Example                             | Required controls                                                           | Residual risk / verification                                       |
| ---------------------- | ----------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Spoofing               | Stolen user refresh token           | Rotation, keyed token hashes, reuse detection, per-device sessions          | Device malware can use active credentials until revoked            |
| Spoofing               | Stolen admin password               | TOTP MFA, short sessions, lockout, step-up MFA                              | Phishing-resistant WebAuthn is a later improvement                 |
| Tampering              | Duplicate approval race             | Row lock, unique constraints, one transaction, idempotency key              | Must be stress-tested against PostgreSQL                           |
| Tampering              | Forged agent command                | mTLS, narrow schemas, operation IDs, authorization allowlist                | Certificate lifecycle and clock skew need runbooks                 |
| Repudiation            | Admin denies revocation             | Append-oriented audit events with actor, target, outcome, request ID        | DB admins remain a high-trust role; export integrity is later work |
| Information disclosure | Token or key in logs                | Structured allowlisted fields, redaction tests, no request-body logging     | Third-party error tooling must be disabled or scrubbed             |
| Information disclosure | Database dump leak                  | Encrypted off-host backups, least privilege, retention, restore audit       | Key custody decision is still required                             |
| Denial of service      | Request/login floods                | Nginx and application rate limits, bounded bodies/timeouts, queue limits    | One VPS remains a single capacity/failure domain                   |
| Elevation of privilege | API command injection reaches host  | No shell endpoint, typed agent API, fixed subprocess argv, hardened service | Agent compromise still exposes WireGuard administration            |
| Elevation of privilege | Arbitrary Xray JSON reaches runtime | Capability registry, typed templates, schema and binary validation          | Template defects require tests and rollback                        |
| Information disclosure | Public Xray subscription URL        | Authenticated profile API, per-device credentials, no public subscriptions  | A compromised device can export its active credential              |
| Tampering              | Invalid protocol/transport pairing  | Reviewed compatibility registry; reject free-form combinations              | Registry updates require security review                           |
| Elevation of privilege | Admin CSRF                          | SameSite=Strict, per-request CSRF tokens, origin checks                     | Browser extensions and local malware remain outside control        |
| Supply chain           | Malicious package or Action         | Lockfiles, pinned Actions SHAs, dependency review, SBOM and image scan      | Scanners do not prove packages are benign                          |

## Security-sensitive flows

### Account request

- Return one neutral response whether the email is new, duplicated, or linked to an
  existing account.
- Normalize email before uniqueness and rate-limit checks.
- Rate limit by network prefix and keyed email hash without logging raw reasons.
- Store the minimum requester data and document its retention.
- Administrator email links only navigate to an authenticated review screen.

### Activation and password reset

- Generate at least 256 bits of randomness.
- Put the raw token only in the TLS-protected link; store a keyed hash in PostgreSQL.
- Consume exactly once in the same transaction that changes the password/state.
- Expire activation after 24 hours and password reset after 30 minutes by default.
- Do not place tokens in analytics, referrers, logs, or error reports. The landing
  page must immediately exchange the token and clear it from browser history.

### Peer provisioning

- Accept only a valid WireGuard public key and registered device ID.
- Enforce user state, expiration, device limit, protocol permission, server
  assignment, and unique address allocation in the database transaction.
- Sign or authenticate the request to the intended agent with mTLS.
- Never accept raw shell, interface names, paths, or arbitrary WireGuard config
  fragments from the API request.
- Revoke the peer before or concurrently with session revocation, record partial
  failures, and retry until desired and actual state converge.

### Xray profile provisioning

- Generate one credential per device/profile and revoke it independently.
- Permit only reviewed protocol/transport/security tuples from the capability
  registry; clients and administrators cannot submit raw Xray JSON.
- Require an outer security layer for VLESS on untrusted networks unless a reviewed
  VLESS Encryption profile is explicitly enabled.
- Render from trusted templates, validate with the pinned Xray binary, atomically
  replace configuration, verify health, and roll back on failure.
- Keep TLS/REALITY private keys and server-side credential encryption keys on the
  host or secret manager, never in Git or API responses.
- Disable Xray access logs by default and use opaque account labels instead of real
  email addresses.

## Privacy and logging

Never collect or log:

- Browsing history or traffic contents
- DNS queries
- Passwords or plaintext authentication/activation/reset tokens
- Client or server private keys
- Complete WireGuard client configurations
- Xray credentials, client profiles, and subscription links
- Email content containing one-time links

Allowed operational metadata is limited to actor/subject IDs, event type, coarse
network information when necessary for abuse defense, request/operation IDs,
timestamps, outcomes, error classes, server health, and aggregate peer handshakes.
Default retention is 365 days for administrator audit events and 90 days for auth
and email operational events, subject to legal and owner review.

## Agent hardening

- Run as a dedicated service identity with only required Linux capabilities.
- Use systemd restrictions such as `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome`, private temporary directories, restricted address families, and a
  small read/write path allowlist.
- Bind the Phase 1 agent to loopback/private interface; never expose it publicly.
- Use fixed binaries and argv arrays; never invoke a shell.
- Validate interface names, IP pools, public keys, Xray capability IDs, credential
  formats, and operation sizes.
- Pin the Xray binary and trusted templates; do not accept paths or config fragments
  over the agent API.
- Keep WireGuard, Xray TLS/REALITY, and credential-encryption private keys root-owned
  with mode `0600`.
- Apply configuration atomically and keep a last-known-good recovery path.

## CI and delivery threats

- Pin third-party GitHub Actions to full commit SHAs.
- Give each job minimal `permissions`; default to read-only contents.
- Do not expose production secrets to pull requests or untrusted forks.
- Generate SBOMs and scan Python, npm, Dart, and container dependencies.
- Run Gitleaks and GitHub secret scanning; block known secret patterns pre-merge.
- Sign or attest release images after the base workflow is stable.
- Deployment remains manual until the owner supplies credentials and explicitly
  authorizes production deployment.

## Residual risks accepted for Phase 1

- A single VPS is a single failure and capacity domain.
- TOTP is vulnerable to sophisticated phishing; WebAuthn is recommended later.
- Email account compromise can expose unused activation/reset links.
- A compromised endpoint can access its own active tunnel and key material.
- Windows and Android kill-switch/leak guarantees require platform tests; they must
  not be marketed as complete before verification.
- VPN agent compromise can alter WireGuard and Xray runtime configuration even
  though it cannot alter application identities without database/API compromise.
- Supporting many Xray combinations increases configuration and fingerprinting
  risk; a profile is not enabled until its exact client/server combination passes
  compatibility, leak, revocation, and rollback tests.
