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
| `NEBULA_MAX_REQUEST_BYTES` | 1 MiB         | Enforced at Nginx and API                      |

## Authentication lifetime defaults

| Variable                            | Default | Security intent                    |
| ----------------------------------- | ------: | ---------------------------------- |
| `NEBULA_ACCESS_TOKEN_TTL_SECONDS`   |     900 | Limit stolen access-token lifetime |
| `NEBULA_REFRESH_TOKEN_TTL_DAYS`     |      30 | Bounded device session             |
| `NEBULA_ACTIVATION_TOKEN_TTL_HOURS` |      24 | Approval activation window         |
| `NEBULA_PASSWORD_RESET_TTL_MINUTES` |      30 | Short recovery exposure            |
| `NEBULA_ADMIN_SESSION_TTL_MINUTES`  |      30 | Short privileged inactivity window |

## Data services

`NEBULA_DATABASE_URL` uses an application role that cannot create roles, databases,
or schema objects. `MIGRATION_DATABASE_URL` uses a separate migration role only for
deployment and local migration commands. The two roles must differ in production.
`REDIS_URL` is internal-only and authenticated in production. PostgreSQL and Redis
ports must not be published to the internet.

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
