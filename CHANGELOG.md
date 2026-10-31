# Changelog

Releases of the apps are on the [releases page](https://github.com/Parsabrg/vpn/releases),
each with its full notes. A server updates to the same tags:
`sudo ./install.sh --update`. Server-side changes take effect when a server is
updated (`install.sh` rerun, or the deploy in `docs/runbooks/deployment.md`).

## Unreleased

### Apps
- Account: change your password, or delete your account. Deletion removes everything
  that names you, and your VPN access on every server; see docs/privacy.md.
- Signing in tells the phone's password manager it worked, so it offers to save the
  password, or to update a saved one that changed; a refused password is never saved.
- A refused token refresh (rate limit, server busy) no longer disconnects the VPN (#20).

### Servers
- The agent's Xray config sets the outbound's IPv4-only resolving in `sockopt`, where
  Xray 26.10 wants it (no deprecation warning; same behaviour).
- `infrastructure/check-protocols.py` proves every protocol a server offers carries
  traffic; the install test runs it after every fresh install.
- Enrolment sends the server's WireGuard range: before, no enrolled server had one,
  and WireGuard on it could give no device an address.
- Admin panel: an action refused because the session is no longer accepted signs out and
  opens the sign-in page, instead of leaving pages whose buttons all fail.
- Approving an account request whose email or username is taken says so (409) instead of
  failing, and a server error no longer leaves the admin panel refusing every later
  action as "session ended".
- Agents trust a CA of the control plane's own, which signs nothing else: no server's
  certificate, old ones included, can call another server's agent. New installs use it
  from the start; existing ones move over with `docs/runbooks/agent-certificates.md`.
- Prometheus metrics for the API and the agent on the server's loopback, and a Grafana
  dashboard (`docs/runbooks/metrics.md`).
- Audit log export as a hash chain (panel: Audit log → Export); `nebula-api audit-verify`
  checks an export, and that a later one still contains an earlier one unchanged.
- `NEBULA_ADMIN_ALLOW` limits the admin panel and admin API to listed addresses.
- `sudo ./install.sh --update` moves a server to the newest release tag, never
  backwards, and shows what changed.
- Login and password-reset limits fit many users behind one shared address (#21).
- Fresh installs: WireGuard clients reach the internet (#22); paths, gRPC name and
  Hysteria2 decoy differ per install (#24); fail2ban, automatic security updates
  and swap (#25); the backup key leaves the server and off-site backups are
  offered (#26).
- Agent certificates are for server use only, the control plane's for client use (#23).
- Admin panel: Content-Security-Policy and Permissions-Policy (#27).
- Xray 26.10.21 on servers (26.9.30 was a pre-release); a rerun of `install.sh` upgrades
  an older Xray and never replaces a newer one. WireGuard range set at install, /20 by
  default (#29).

## 0.1.33 — 2026-10-30

The first release from this repository.

- Stalled connections are caught in about 20 seconds by a small real download.
- Protocol test with download speed on Windows and Linux.
- Several servers on one account work side by side.

Releases up to 0.1.32 came from the private development repository.
