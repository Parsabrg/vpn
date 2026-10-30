# Environment and secret contract

`.env.example` contains development placeholders. Production Compose should use
non-secret environment variables plus Docker secret files or an external secret
manager. Variables ending in `_FILE` point to mounted files and must not contain the
secret value itself.

## Required owner-supplied values

| Setting                        | Purpose                                 |                        Secret |
| ------------------------------ | --------------------------------------- | ----------------------------: |
| `NEBULA_DOMAIN`                | Public API/admin/VPN DNS base           |                            No |
| `NEBULA_ACME_EMAIL`            | TLS certificate notices                 |                            No |
| `NEBULA_ADMIN_EMAIL`           | Initial admin and request notifications |                 Personal data |
| `NEBULA_EMAIL_PROVIDER`        | `smtp` or `resend`                      |                            No |
| SMTP host/user or Resend key   | Production delivery                     |        Key/password is secret |
| `NEBULA_WG_PUBLIC_ENDPOINT`    | Client tunnel endpoint                  |                            No |
| `NEBULA_XRAY_PUBLIC_HOST`      | Xray profile hostname                   |                            No |
| VPS public IP and SSH policy   | Deployment target                       | Access credentials are secret |
| `NEBULA_BACKUP_REMOTE`         | Off-host backup destination             |                    Usually no |
| Backup destination credentials | Backup upload                           |                           Yes |
| `NEBULA_BACKUP_AGE_RECIPIENT`  | Public encryption recipient             |                            No |

## Generated secrets

Generate these outside Git during deployment:

- PostgreSQL password
- Ed25519 JWT signing private key and public key
- Token hashing pepper
- MFA seed-encryption key
- Protocol-credential envelope-encryption key
- SMTP password or Resend API key
- Agent CA, API client certificate/key, and agent server certificate/key
- WireGuard server private key
- Xray TLS/REALITY private keys and per-profile server secrets
- Backup destination credentials and offline age private identity

The initial administrator password is entered interactively into the seed command;
it is never accepted as an environment variable or command-line argument.

## Application settings

| Variable                   | Default       | Notes                                          |
| -------------------------- | ------------- | ---------------------------------------------- |
| `NEBULA_ENV`               | `development` | Production refuses unsafe development defaults |
| `NEBULA_LOG_LEVEL`         | `INFO`        | Structured logs with allowlisted fields        |
| `NEBULA_API_PUBLIC_URL`    | local URL     | Used for API links and issuer validation       |
| `NEBULA_ADMIN_PUBLIC_URL`  | local URL     | Activation/review destinations                 |
| `NEBULA_ALLOWED_ORIGINS`   | local admin   | Exact origins only; never `*` with credentials |
| `NEBULA_MAX_REQUEST_BYTES` | 1 MiB         | Enforced by API; match at the edge proxy       |

## Authentication key material

| Variable                                  | Format                           | Purpose                                |
| ----------------------------------------- | -------------------------------- | -------------------------------------- |
| `NEBULA_JWT_PRIVATE_KEY_FILE`             | Ed25519 private key in PEM       | Sign user access tokens                |
| `NEBULA_JWT_PUBLIC_KEY_FILE`              | Matching Ed25519 public PEM      | Verify user access tokens              |
| `NEBULA_JWT_PREVIOUS_PUBLIC_KEYS_DIR`     | Directory of Ed25519 public PEMs | Retired verification keys (optional)   |
| `NEBULA_TOKEN_PEPPER_FILE`                | Exactly 32 raw random bytes      | Key opaque-token digests               |
| `NEBULA_TOKEN_PREVIOUS_PEPPERS_DIR`       | Directory of 32-byte files       | Retired token peppers (optional)       |
| `NEBULA_MFA_ENCRYPTION_KEY_FILE`          | Exactly 32 raw random bytes      | Encrypt administrator TOTP seed        |
| `NEBULA_MFA_PREVIOUS_ENCRYPTION_KEYS_DIR` | Directory of 32-byte files       | Retired MFA encryption keys (optional) |
| `NEBULA_JWT_KEY_ID`                       | `v1`                             | JWT verification-key version           |
| `NEBULA_TOKEN_KEY_VERSION`                | `1`                              | Opaque-token pepper version            |
| `NEBULA_MFA_KEY_VERSION`                  | `1`                              | MFA encryption-key version             |

The four `_FILE` paths are required together outside development and tests; production
requires absolute paths. Development and tests may omit all four and use process-local
ephemeral keys. That fallback is single-process only: restarting invalidates existing
tokens and leaves MFA ciphertext created by the previous process unreadable.

The three `_DIR` settings are always optional, including in production (a fresh deployment
has no retired keys yet), but must be absolute when set. Each is a directory holding one
file per retired key, named exactly by that key's old `kid`/version -- e.g. a retired JWT
key that was `NEBULA_JWT_KEY_ID=v1` becomes `$NEBULA_JWT_PREVIOUS_PUBLIC_KEYS_DIR/v1`, and a
retired `NEBULA_TOKEN_KEY_VERSION=2` pepper becomes `$NEBULA_TOKEN_PREVIOUS_PEPPERS_DIR/2`.
This lets an outgoing key keep verifying/decrypting existing tokens and ciphertext while a
new key handles everything newly issued -- rotation without invalidating what's already out
there. Generate new key material with `nebula-api generate-jwt-signing-key` or
`nebula-api generate-symmetric-key`; these commands only ever write fresh files; they never
touch environment variables or move anything into a `_DIR`, since that's a deployment
decision the operator makes explicitly.

### Key rotation procedure

`docs/runbooks/encryption-key-rotation.md` has the step-by-step, including the two traps
specific to the production host (the secrets directory is mounted read-only into the
containers, and the container reads them through group `nebula-secrets`, not as root).

Each key type has a different window before its retired file is safe to delete -- deleting
too early can suddenly invalidate something still in use.

- **JWT signing key**: access tokens are short-lived (`NEBULA_ACCESS_TOKEN_TTL_SECONDS`,
  bounded to at most 3600s). Generate a new keypair, deploy it under a new
  `NEBULA_JWT_KEY_ID` with the old public key moved into
  `NEBULA_JWT_PREVIOUS_PUBLIC_KEYS_DIR` under its old `kid`, and restart. Safe to delete the
  retired public key file after a conservative 24h -- enough margin for the configured TTL,
  clock skew, and any request already in flight when the restart happened.
- **Token pepper**: shared by every opaque-token consumer (refresh tokens, password resets,
  activation, account requests), whose TTLs run up to 90 days
  (`NEBULA_REFRESH_TOKEN_TTL_DAYS`/`NEBULA_ACCOUNT_REQUEST_TTL_DAYS`). Generate a new pepper,
  deploy it under a new `NEBULA_TOKEN_KEY_VERSION` with the old pepper moved into
  `NEBULA_TOKEN_PREVIOUS_PEPPERS_DIR` under its old version, and restart. Only delete the
  retired pepper once the longest configured opaque-token TTL has fully elapsed since that
  rotation -- deleting sooner can invalidate a refresh or account-request token minted just
  before the switch.
- **MFA encryption key**: there is no automatic re-encryption sweep -- an administrator's
  encrypted TOTP seed stays under whatever `key_version` originally encrypted it until they
  re-enroll MFA, which may be a long time or never. Generate a new key, deploy it under a
  new `NEBULA_MFA_KEY_VERSION` with the old key moved into
  `NEBULA_MFA_PREVIOUS_ENCRYPTION_KEYS_DIR` under its old version, and restart. There is no
  time-bound safe-retirement window for this one: never delete a retired MFA key file on a
  schedule, only after confirming via a direct database query that zero
  `admin_totp_credentials` rows still reference that `key_version`.
- **Xray encryption key**: encrypts every device's VPN credential, and there is no
  re-encryption sweep either -- a credential stays under whatever `key_version` wrote it
  until the device is re-provisioned. Generate a new key, deploy it under a new
  `NEBULA_XRAY_KEY_VERSION` with the old key moved into
  `NEBULA_XRAY_PREVIOUS_ENCRYPTION_KEYS_DIR` under its old version, and restart. Only delete
  a retired key once `select key_version, count(*) from device_protocol_credentials where
ciphertext is not null group by key_version` shows nothing left under it. Losing it is
  worse than losing the MFA key's predecessor: an undecryptable credential can be neither
  served nor cleanly revoked, so the device has to be re-provisioned. This is the rotation
  that has already gone wrong once here; the runbook opens with what happened.

## Authentication lifetime defaults

| Variable                                  | Default | Security intent                    |
| ----------------------------------------- | ------: | ---------------------------------- |
| `NEBULA_ACCESS_TOKEN_TTL_SECONDS`         |     900 | Limit stolen access-token lifetime |
| `NEBULA_REFRESH_TOKEN_TTL_DAYS`           |      30 | Fixed device-session family        |
| `NEBULA_ACTIVATION_TOKEN_TTL_HOURS`       |      24 | Approval activation window         |
| `NEBULA_PASSWORD_RESET_TTL_MINUTES`       |      30 | Short recovery exposure            |
| `NEBULA_ADMIN_SESSION_TTL_MINUTES`        |      30 | Privileged inactivity window       |
| `NEBULA_ADMIN_SESSION_ABSOLUTE_TTL_HOURS` |       8 | Non-extendable privileged lifetime |
| `NEBULA_ADMIN_PREAUTH_TTL_MINUTES`        |       5 | Password success grants no session |
| `NEBULA_ADMIN_STEP_UP_TTL_MINUTES`        |       5 | Bound destructive-action elevation |
| `NEBULA_TOTP_ALLOWED_SKEW_STEPS`          |       1 | Small clock-drift allowance        |

## Authentication abuse controls

| Variable                           | Default | Scope                                                        |
| ---------------------------------- | ------: | ------------------------------------------------------------ |
| `NEBULA_AUTH_RATE_WINDOW_SECONDS`  |     900 | Atomic Redis limiter window                                  |
| `NEBULA_USER_LOGIN_RATE_LIMIT`     |      10 | Per account for sign-in; per token for refresh               |
| `NEBULA_USER_NETWORK_RATE_LIMIT`   |     100 | Per /24, sign-in and password reset (carrier NAT, VPN exits) |
| `NEBULA_ADMIN_LOGIN_RATE_LIMIT`    |       5 | Keyed admin plus coarse network prefix                       |
| `NEBULA_ADMIN_MFA_RATE_LIMIT`      |       5 | Challenge plus coarse network prefix                         |
| `NEBULA_PASSWORD_RESET_RATE_LIMIT` |       5 | Per account (request) or token (confirm)                     |
| `NEBULA_ADMIN_LOCKOUT_THRESHOLD`   |       5 | Password or MFA failures before lockout                      |
| `NEBULA_ADMIN_LOCKOUT_SECONDS`     |     900 | Lockout duration                                             |

Forwarding headers are ignored for these controls; the socket peer is reduced to a
coarse `/24` IPv4 or `/64` IPv6 prefix. A later trusted-proxy deployment must make
that boundary explicit before forwarded client addresses are used.

## Data services

`NEBULA_DATABASE_URL` uses an application role that cannot create roles, databases,
or schema objects. `MIGRATION_DATABASE_URL` uses a separate migration role only for
deployment and local migration commands. The two roles must differ in production.
`NEBULA_REDIS_URL` is internal-only and authenticated in production. PostgreSQL and
Redis ports must not be published to the internet. Readiness requires both the exact
PostgreSQL migration head and a successful Redis ping.

Redis production policy is AOF persistence with `appendfsync everysec`. Jobs and
sessions may be reconstructed or invalidated, while PostgreSQL remains authoritative
for approval, identity, assignment, email intent, and provisioning state.

## Email provider behavior

SMTP is suitable for arbitrary providers and local Mailpit development. Resend is
the first API provider. Only the worker reads provider credentials. Email delivery
rows store template name, recipient, status, attempts, and redacted provider result;
they do not retain raw one-time links in logs.

## VPN agent and protocol configuration

The shared agent uses mTLS and a typed protocol-driver contract. Static binary,
directory, and secret-file paths come from the host environment. User-selectable
protocol combinations come from a reviewed database capability registry and cannot
be created from arbitrary environment strings or API-supplied JSON.

### WireGuard

Agent settings are host-side only. `NEBULA_WG_CLIENT_POOL` must not overlap the VPS
LAN, Docker networks, or common client networks. The deployment preflight command
must reject overlaps and a pool too small for configured device limits.

`NEBULA_WG_CLIENT_ALLOWED_IPS=0.0.0.0/0,::/0` represents full tunnel. IPv6 must not
be advertised until routing and leak protection are tested; the safer initial
deployment may temporarily use IPv4-only `0.0.0.0/0` and document that limitation.

### Xray-core

`NEBULA_XRAY_ENABLED` remains false until an Xray delivery milestone is deployed and
verified. The host pins `NEBULA_XRAY_BINARY`, owns its configuration/state
directories, and mounts TLS/REALITY keys through root-readable secret files. The
agent validates a complete candidate before atomic apply and rollback.

Xray access logging is disabled by default. Enabling operational statistics must
use opaque internal labels and must not collect destinations, DNS queries, traffic
content, client profiles, or credentials.

Transport paths, service names, ports, and TLS/REALITY settings belong to reviewed
server profile records. They are not authentication secrets, but changing them can
break clients and therefore requires versioned rollout and compatibility tests.

## Retention and backups

Default retention:

- Administrator audit logs: 365 days
- Authentication operational logs: 90 days
- Email-delivery metadata: 90 days
- Encrypted backups: 30 days

Backups must be encrypted before leaving the VPS, copied off-host, checked for age
and size daily, and restored in a scheduled exercise. A backup is not considered
working until a clean restore test passes.
