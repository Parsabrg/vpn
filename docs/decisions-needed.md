# Decisions and credentials needed

No real credential should be pasted into a GitHub issue, pull request, chat message,
`.env`, or command history. Supply secrets through the chosen deployment secret
mechanism when implementation reaches that integration point.

## GitHub access — completed

The connected GitHub integration now has access to `Parsabrg/vpn`. `main` is
initialized and the Phase 0 files are available in draft pull request #1.

## Needed before Phase 1.1

1. **Repository visibility:** confirm whether this security-sensitive project should
   remain public. Public source is viable, but it increases the importance of never
   committing infrastructure details or secrets.
2. **License:** choose a source license or mark the repository proprietary. Do not
   add a license by assumption.
3. **Supported versions:** confirm minimum Android API level and Windows versions.

## Needed before production email tests

1. Administrator email address.
2. Provider choice: SMTP or Resend. SMTP is more portable; Resend generally gives
   easier API delivery observability.
3. Sender domain/address and confirmation that DNS verification can be configured.
4. Whether rejected applicants receive an email by default.
5. Privacy/contact wording and requester-data retention period.

## Needed before VPS integration

1. Domain/subdomains for admin/API, WireGuard, and future Xray endpoints.
2. Ubuntu version, VPS provider, public IPv4/IPv6 availability, CPU/RAM/disk, and
   whether nested/container networking restrictions exist.
3. SSH administrator access policy and firewall ownership. Do not send a private
   SSH key through chat or Git.
4. Expected maximum users, devices per user, and concurrent tunnels. This determines
   the WireGuard pool, Xray process limits, and VPS sizing.
5. Preferred client tunnel CIDR after checking overlap with VPS and Docker networks.
6. Whether IPv6 full-tunnel support is required in the first release. It should not
   be advertised until routing and leak tests pass.

## Needed before backup completion

1. Off-host destination (S3-compatible object store, restic repository, or other).
2. Retention and recovery-point/recovery-time objectives.
3. Custodian for the offline age private identity. Losing it makes backups
   unrecoverable; exposing it defeats backup encryption.
4. Restore-test cadence and acceptable maintenance window.

## Recommended defaults unless you choose otherwise

| Decision            | Recommended Phase 1 default                                    |
| ------------------- | -------------------------------------------------------------- |
| Email API provider  | Resend plus SMTP abstraction and Mailpit locally               |
| Admin MFA           | TOTP with single-use recovery codes; WebAuthn in a later phase |
| User access token   | Ed25519 JWT, 15 minutes                                        |
| User refresh token  | Opaque rotating token, 30-day maximum family                   |
| Admin session       | Opaque Redis session, 30-minute inactivity timeout             |
| Activation/reset    | 24 hours / 30 minutes                                          |
| Initial tunnel mode | IPv4 full tunnel; add IPv6 only after leak verification        |
| Redis persistence   | AOF `everysec`, no public port                                 |
| Merge strategy      | Protected `main`, reviewed squash merge                        |
| Deployment          | Manual production approval; no automatic deploy from PRs       |

## Needed before the first Xray milestone

1. Choose the initial public profiles. Recommended starting profiles are VLESS over
   XHTTP with TLS and VLESS over RAW with REALITY/XTLS Vision; compatibility modes
   are enabled only after separate tests.
2. Decide whether TLS terminates in Xray or a reverse proxy for each profile.
3. Confirm domain, ports, CDN/reverse-proxy use, UDP requirements, and firewall
   ownership.
4. Approve the Android and Windows Xray-core packaging/licensing approach and the
   privileged TUN/Wintun boundary.
5. Decide whether authenticated profile export is allowed. Public or long-lived
   subscription URLs are not recommended.
6. Approve the profile deprecation and client migration policy before legacy
   transports are enabled.

## Not required yet

- Production deployment credentials
- Apple developer account
- Production Xray profile values during the WireGuard-only Phase 1 work
- Multiple VPN hosts
- Payment or subscription provider

Those belong to later authorized phases and must not delay the protocol-neutral
control plane and WireGuard lifecycle.
