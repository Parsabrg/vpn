# ADR 0002: Phase 1.3 authentication boundaries

- Status: accepted
- Date: 2026-07-20

## Context

Phase 1.3 introduces internet-facing authentication for ordinary users and a
separate privileged administrator realm. Authentication must support immediate
revocation, refresh-token reuse detection, MFA enrollment for the seeded owner,
and future key rotation without storing plaintext credentials. PostgreSQL remains
authoritative for identity and user sessions; Redis holds only reconstructible,
short-lived security state.

Password-reset token issuance belongs to this milestone, while reliable email
delivery belongs to Phase 1.4. The boundary must not create an endpoint that leaks
a reset token or a durable outbox row containing raw link material.

## Decision

### Separate realms

- Users and administrators remain separate identities even when their normalized
  email addresses match. User bearer tokens never authorize administrator routes,
  and administrator cookies never authorize user routes.
- User access tokens are Ed25519 JWTs with a fixed `EdDSA` algorithm, explicit
  `at+jwt` type, issuer, audience, key ID, token-use marker, user, session,
  issued/not-before/expiry times, and unique token ID. Every protected request also
  reloads the user, device, and PostgreSQL session so revocation is immediate.
- User refresh tokens are 256-bit opaque values stored only as domain-separated,
  keyed SHA-256 digests. Exactly one active refresh token exists per session.
  Rotation locks the current token and session in one transaction. Reuse revokes
  the whole session family and all active descendants.
- A registered device has at most one active user session. Login always creates a
  new server-generated session and family; client-provided session identifiers are
  ignored.

### Administrator authentication

- Administrators authenticate with Argon2id password verification followed by
  TOTP or a single-use recovery code. Password success creates only a short-lived,
  single-use Redis pre-auth challenge and grants no administrator authority.
- A seeded administrator without MFA may use that challenge only to enroll TOTP.
  The seed is encrypted with AES-256-GCM and associated data binding the credential
  to the administrator. The accepted TOTP timestep is persisted and advanced under
  a row lock, preventing replay across processes and concurrent requests.
- Full administrator sessions are new 256-bit opaque values. Redis keys contain
  only keyed digests. Cookies are host-only, HttpOnly, SameSite Strict, scoped to
  `/`, and Secure in staging/production. Redis failure invalidates the session and
  fails authentication closed.
- Unsafe cookie-authenticated requests require an exact allowed `Origin` and a
  session-bound synchronizer token. CSRF comparison and rotation are atomic.
  Once consumed, the replacement is returned in both successful and failed action
  responses so a valid session cannot be stranded on the previous token.
  Step-up MFA rotates the administrator session and is required by later phases for
  destructive actions.

### Abuse resistance and secrets

- Login, MFA, refresh, and reset issuance/consumption use atomic Redis limits for a
  keyed canonical-account/token bucket and a coarse network-prefix bucket.
  Forwarding headers are ignored unless a later deployment explicitly configures
  trusted proxies.
- Unknown identities still perform a fixed Argon2id verification against a dummy
  hash. Public failures do not distinguish unknown, disabled, expired, locked, or
  incorrect credentials.
- Signing keys, token peppers, and MFA encryption keys are loaded from files in
  production. Development and tests may generate process-local ephemeral material;
  a restart intentionally invalidates affected credentials and this fallback is
  not suitable for multiple workers.
- Access, refresh, reset, pre-auth, session, CSRF, TOTP, and recovery values are
  excluded from logs, validation responses, audit records, model representations,
  and email-delivery metadata.

### Password-reset delivery boundary

- Phase 1.3 owns generation, keyed-digest persistence, single-use consumption,
  password replacement, and revocation of all existing sessions in one database
  transaction.
- The public request endpoint always returns the same accepted response and never
  returns the token. Token delivery is an injected boundary. Until Phase 1.4 adds
  its reviewed email worker handoff, production must not claim reset email delivery
  is operational.
- Phase 1.4 must pass raw link material directly to a protected delivery boundary
  or add reviewed envelope-encrypted transient storage. It must not place raw reset
  tokens in `email_deliveries`, logs, URLs recorded by analytics, or error reports.

## Consequences

- Authentication requires both PostgreSQL and Redis readiness. Losing Redis logs
  administrators out and temporarily denies authentication attempts rather than
  silently disabling limits.
- Key versions are stored beside keyed digests/ciphertext. The current file contract
  loads one active version; a later operational milestone must add a reviewed
  multi-key rotation window before claiming non-disruptive rotation. Unknown
  versions fail closed.
- The fixed refresh-family lifetime is bounded by the PostgreSQL session expiry;
  rotation never extends it.
- CI upgrades a real PostgreSQL database and exercises the deferred refresh lineage
  and active-session/token constraints. A real Redis test exercises the Lua-backed
  limiter, lockout, pre-auth, session, CSRF, and rotation transitions. Service and
  cryptographic tests use row-lock-aware fakes, injected clocks, and deterministic
  randomness for replay and recovery-code boundaries.
