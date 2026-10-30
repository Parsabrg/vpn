# Changelog

Releases of the apps are on the [releases page](https://github.com/Parsabrg/vpn/releases),
each with its full notes. A server updates to the same tags:
`sudo ./install.sh --update`. Server-side changes take effect when a server is
updated (`install.sh` rerun, or the deploy in `docs/runbooks/deployment.md`).

## Unreleased

### Apps
- A refused token refresh (rate limit, server busy) no longer disconnects the VPN (#20).

### Servers
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
- Xray 26.9.30 on servers, as in the apps; WireGuard range set at install, /20 by
  default (#29).

## 0.1.33 — 2026-10-30

The first release from this repository.

- Stalled connections are caught in about 20 seconds by a small real download.
- Protocol test with download speed on Windows and Linux.
- Several servers on one account work side by side.

Releases up to 0.1.32 came from the private development repository.
