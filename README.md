# Nebula VPN

Nebula VPN is a self-hosted VPN built for networks that filter and throttle,
Iran's first. One server runs the control plane and the VPN; the apps for
Android, Windows and Linux connect to it with whichever protocol the network
lets through, and keep working when the server's own address is blocked.

Releases are on the [releases page](https://github.com/Parsabrg/vpn/releases).
[`docs/ROADMAP.md`](docs/ROADMAP.md) says what comes next, and its status table is the
record of what is done and how it was tested; the full target is in
[`docs/roadmap-sections.md`](docs/roadmap-sections.md).

## What it does

- **Protocols:** VLESS over WebSocket, gRPC, XHTTP and raw TCP+TLS (Xray),
  Hysteria2, and WireGuard. *Automatic* tests them on the network the phone
  is on and keeps a score per protocol and server.
- **Getting past blocks:** the app reaches its API directly, through a
  Cloudflare route with ECH, or through a web-host front (Vercel), races a
  stalled request down the next route, and learns new routes from the
  server without a new build. Tunnels cross the CDN when one is configured;
  a scan finds the cleanest Cloudflare address from the device.
- **Free mode:** without a server or an account, the app connects through a
  Cloudflare Worker relay ([`services/edge-relay`](services/edge-relay)), or
  through links and subscriptions the person adds (VLESS, REALITY, Trojan,
  Shadowsocks, Hysteria2).
- **Routing:** sanctioned services (sites that block Iran) through the VPN
  and everything else direct, Iranian sites direct, local network direct.
  Switches apply to a live connection at once.
- **Protection:** kill switch on Windows and Linux, Android's always-on VPN,
  continuous tunnel health checks with reconnect, DNS through the tunnel.
- **Accounts:** no public sign-up. People request access, an administrator
  approves, the person sets a password from a single-use link. Device limits,
  account expiry and per-device revocation.
- **Admin panel:** users and requests, devices and their online status,
  server controls (active, maintenance, disabled), usage, and a security
  dashboard.
- **Operations:** encrypted nightly backups off the host with a tested
  restore, health and reachability timers with alerts, signed releases with
  an SBOM, an update check in the apps.
- **Languages:** English, Persian, Arabic, Turkish, Russian, Chinese,
  German, French, Spanish and Dutch.

## Design principles

- No unrestricted public registration.
- Client WireGuard private keys never leave the device.
- Xray credentials are unique per device and never exposed through public
  subscription URLs, logs, analytics or error reports.
- No connection logs and no IP addresses kept; see
  [`docs/privacy.md`](docs/privacy.md).
- The public API never gets root or a shell. VPN changes go through narrow
  WireGuard, Xray and Hysteria2 drivers behind a mutually authenticated
  agent.
- Secrets live in files outside Git, never in the repository.

## Workspaces

```text
apps/
  admin/          Next.js administrator panel
  mobile/         Flutter app for Android, Windows and Linux
services/
  api/            FastAPI control plane (also the migrate, usage and prune jobs)
  worker/         Mail delivery from the API's outbox
  vpn-agent/      Root-side agent that drives WireGuard, Xray and Hysteria2
  edge-relay/     Cloudflare Worker relay for free mode
infrastructure/
  compose/        Development and production Compose files
  nginx/          Reverse proxy, TLS and the CDN route
  systemd/        Units and timers for the agent, Xray, Hysteria2, backups
  backup/         Backup and restore
  polkit/         What the agent may restart
docs/             Architecture, threat model, ADRs, runbooks, roadmap
.github/          CI on GitHub-hosted runners, security scans, Dependabot
```

## Documents

[CHANGELOG.md](CHANGELOG.md) lists changes; [CONTRIBUTING.md](CONTRIBUTING.md) says how to send one;
[SECURITY.md](SECURITY.md) says how to report a vulnerability privately.

Pull requests written as "archive #N" are in the private development history
this repository was published from; plain "#N" is a pull request here.

- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md)
- [Deployment](docs/runbooks/deployment.md) and
  [environment variables](docs/environment.md)
- [Client releases](docs/runbooks/client-release.md)
- [Monitoring](docs/runbooks/monitoring.md)
- [Production-readiness audit](docs/runbooks/production-readiness-audit.md)
- [Going public](docs/runbooks/going-public.md)
- [Development guide](docs/development.md): toolchain, quality gates and the
  loopback-only Compose stack

## Install a server

On a fresh Ubuntu or Debian VPS (2 GB of memory is enough), as root:

```bash
git clone <this repository> nebula && cd nebula && sudo ./install.sh
```

It asks for a domain, the administrator's email, how to send email, and
finally the administrator's password; everything else (Docker, keys, the
certificate, nginx, the firewall, Xray, Hysteria2, WireGuard, the VPN agent,
the protocols, daily encrypted backups) is done for you, in about 15
minutes. Before it asks for the certificate it tells you the two DNS records
to create. Rerun it at any time to change the answers; it keeps everything
already set up. To update, `sudo ./install.sh --update` moves the checkout to
the newest release tag (never backwards, never over local changes), lists what
changed, and reruns from it; `--update v0.1.34` picks a release.
[CHANGELOG.md](CHANGELOG.md) says what each release changed.

- **Server inside Iran:** PyPI's download host is unreachable there. The
  installer notices and asks for an HTTP proxy for the build. Pick a domain
  that is not filtered in Iran: DuckDNS names cannot get a certificate there.
- **Backups:** kept encrypted in `/var/backups/nebula`. The installer shows
  the backup key once; keep it off the server. On a new server,
  `sudo ./install.sh --restore <backup file>` brings everything back: users,
  devices, keys and the server's identity.
- **Protocols and ports:** `sudo ./install.sh --configure` turns protocols
  on or off (including Shadowsocks-2022, VLESS Encryption and VMess) and
  changes their ports; the firewall, nginx, WireGuard and the server's offer
  to apps follow. Nebula writes Xray's configuration itself, so editing it by
  hand is overwritten.
- **Admin panel from known addresses only:**
  `sudo NEBULA_ADMIN_ALLOW=203.0.113.7,198.51.100.0/24 ./install.sh` lets only
  those addresses open the panel and the admin API; everyone else gets 403.
  The app's API is not affected. `NEBULA_ADMIN_ALLOW=any` opens it again.
  Over the VPN is not an option: VPN clients are kept away from the server
  itself.
- **More servers:** the panel's Server health → **Add server** gives a
  one-line `install.sh --join` command for the new machine.
- **Apps:** in the app, "Connect to your server" takes the address the
  installer prints, or the pairing link from the admin panel.

## Local configuration

Copy `.env.example` only for local development and replace placeholders outside
Git. Production secrets are mounted as files. Do not commit `.env`, private
keys, certificates, WireGuard configurations, Xray profiles, subscription
links or database backups.

## License

Nebula VPN is free software, licensed under the GNU General Public License,
version 3 or (at your option) any later version: see [LICENSE](LICENSE).
The third-party software it ships or builds on, and their licenses, are
listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); the app shows
them under Settings > Open-source licenses.
