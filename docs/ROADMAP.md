# Nebula VPN — Roadmap

What comes next, and the status of what is done. The full target, adopted
2026-10-01, is in [roadmap-sections.md](roadmap-sections.md): sections 1–109,
with section 108 giving the recommended order. "Section N" below and in the
status table refers to that file.

> One control plane, one account/device system, one client experience,
> multiple VPN nodes, multiple connection engines, centralized policy, strong
> security, automatic recovery, privacy-focused DNS, routing, monitoring, and
> administration.

## Next

From the improvement list reviewed 2026-10-30. Items marked *plan* get a
written plan (or an ADR in `docs/adr/`) and the owner's OK before building.

**Censorship**
- *plan* VLESS + REALITY (Vision, XHTTP) on the server, no domain or certificate needed (section 4).
- *plan* Everything on port 443, TCP and UDP, split by name with nginx `ssl_preread`.
- *plan* AmneziaWG as an engine, server and apps (section 4).
- *plan* Relay role: a server inside Iran forwarding to one abroad (section 23).
- Hysteria2 port hopping on the server, allowed in the app.
- *plan* Each user gets only some of the backup routes, so one leaked account does not reveal all.
- *plan* DNS tunnelling as a last-resort route (ADR 0004).
- A second CDN route on CloudFront: the server side is done; the distribution needs the owner's AWS account (section 11).

**Security and admin**
- Passkeys for admin sign-in, alongside TOTP.
- Manage admins in the panel: invite, roles, disable, sessions.
- Admin panel open only to an IP allowlist or over the VPN.
- Tamper-evident audit log export (section 90).

**Running servers**
- *plan* Signed server images and an offline bundle with each release.
- `install.sh` tested in CI on a fresh Ubuntu machine (new install, rerun, `--join`).
- Metrics: a Prometheus endpoint on localhost for the API and agent, and charts.
- *plan* Upgrade servers from the panel, with health checks and rollback (section 2).
- Versioned server releases: `install.sh` updates to a tag, with a changelog.

**Apps**
- *plan* In-app updater that checks the release signature before installing.
- Signed Windows builds (SignPath, needs the owner's sign-up).
- *plan* iOS and macOS apps.
- `devices_controller.dart` split by concern, no change in behaviour.
- Persian (right-to-left) admin panel.
- Self-service in the app: change password, remove own device, delete own account (sections 59, 100).

**Project**
- Releases built in GitHub Actions on a tag, with build attestations.
- Python dependencies locked with hashes and installed with `--require-hashes`.
- A second maintainer, and how someone else cuts releases and runs the servers.


## Status

Updated in the same pull request as the work (section 92).

| Section | Item | State |
| --- | --- | --- |
| 38, 108 F42 | Platform-wide accumulated traffic by engine, exact byte totals and newest collection timestamps in admin | Done, archive #274 |
| 12, 15, 26, 33, 108 D26 | Nebula's own resolver for Xray clients: AdGuard Home on the server (no filtering, no query log, no statistics, DNS-over-HTTPS upstreams), reached through a reserved address the agent redirects; the API hands it out as `client_dns` | Done, archive #364; live, seen on the phone (DNS 198.18.0.53) |
| 13, 108 D27-D29 | DNS profiles: an admin gives an account default (the server's own resolver), ads or family, and a device may override it; the API hands Xray clients the matching resolvers; set from the user page in the admin panel (step-up, audited) | Done, archive #365; deployed (migration 0018), default profile seen on the phone |
| 21, 108 E39 | Routing by address as well as by name: "Websites that skip the VPN" takes IP addresses and ranges (IPv4 and IPv6, never /0), which go direct by an Xray `ip` rule | Done, archive #366 (0.1.27); on the phone an exempted IP went direct while the rest exited through the server |
| 16, 108 I66 | IPv6 fails closed on every platform: WireGuard claims ::/0, the Android, Windows and Linux Xray tunnels claim it without carrying it, so nothing leaks around the tunnel; carrying IPv6 stays off (mixed families broke YouTube, archive #352) | Done (verified 2026-10-19) |
| 41, 108 B11 | Admin Xray listener health for enabled Xray nodes: independent state, UTC evidence times, latency and safe errors; WireGuard evidence timestamp | Done, archive #273 |
| 3, 40, 108 F49 | Reconciliation triage evidence: safe failure reasons, repair-operation correlation, uncertain repair responses recorded as ambiguous | Done, archive #272 |
| 3, 40, 108 F49 | Reconciliation history: recorded outcomes, timestamps, generations and safe error codes; filter by server, target or outcome; paginated target history | Done, archive #271 |
| 3, 40, 108 F49 | Server health shows pending provisioning, pending removals and failed runtime records for every server across WireGuard, Xray and Hysteria2 | Done, archive #270 |
| 69 | API PyJWT 2.15.0 clears the retry PR's dependency-audit blocker (PYSEC-2026-4141) | Done, archive #268 |
| 3, 106 | Failed WireGuard, Xray and Hysteria2 removals stay pending through repeated failures and retry until confirmed revoked | Done, archive #268 |
| 11 | Clean Cloudflare address: scan from the device, use the fastest for the CDN route (0.1.20) | Done, archive #265 |
| 11 | Cloudflare dial fallbacks: a Cloudflare tunnel that carries nothing is redialled plain (clean IP, Chrome, the transport's ALPN), then "F&F" (zero-length TLS hello split, unsafe fingerprint, Python cipher order; reported for Irancell's firewall), then over Cloudflare's IPv6 edge (reported for Hamrah-e-Avval's, only with IPv6); the dial that carried is tried first next time | Done, branch `cdn-dial-fallbacks`; plain dial 1/4 + full 3 MB on a TCI line, F&F/IPv6 untested on their own firewalls |
| 11 | Cloudflare's ECH blocked from Iran (2026-10-21: `cloudflare-ech.com` unanswered, the CDN route carried nothing with or without ECH or a split hello): XHTTP goes through the Vercel front again on every route, WebSocket and gRPC stay on Cloudflare | Done, archive #378; superseded 2026-10-29: the Vercel front ran out of its free quota and was removed from the routes; Automatic now finds a direct protocol (VLESS TCP+TLS, WireGuard) when Cloudflare stalls |
| 3, 40, 108 F49 | Operator repair controls: "Run reconciliation now" and, on ambiguous or failed history rows, "Check again" for one credential; both run the scheduled passes' own code (repair only safe drift, never widen access), audited, kept apart from the 15-minute sweep by a PostgreSQL advisory lock | Done, archive #375; live 2026-10-20 (12 Xray clients in sync; a second concurrent sweep skipped) |
| 11 | Shadowsocks-2022 straight to the server (learned from Lantern, which carries Iranian users over it to Alibaba Cloud): the address Iran stalls for TLS carried it at 40-80 Mbit/s from the home line and 31-58 Mbit/s on the phone, 2026-10-22. Agent inbound with live user changes, per-client key from the UUID, `seed-ss2022-protocol`, app reads `protocol`/`method`/`password` | Done, archive #381; deployed 2026-10-23, released in 0.1.29 (pre-release); fails on MCI mobile data |
| 11 | VLESS Encryption and VMess (raw, WebSocket) straight to the server, no TLS: 53 and 39-47 Mbit/s from the home line, 2026-10-22; like Shadowsocks-2022 they fail on MCI mobile data, where Vercel stays the route. Agent inbounds with live users, `seed-direct-protocols`, the app's VMess outbound and VLESS `encryption` | Done, archive #381 + archive #383; deployed 2026-10-23, released in 0.1.29 (pre-release) |
| 44, 45 | External monitoring: a Cloudflare Worker (`services/uptime-monitor`) asks the CDN route an API question every 15 minutes and emails the owner through Cloudflare Email Routing while it fails; a test alert reached the inbox | Done, 2026-10-20; the Vercel front dropped from its targets 2026-10-30 |
| 11 | A route's refusal that is not the API's (no JSON `detail`) counts as a dead route: a disabled Vercel front answered every request "402 Payment required" and the app showed "Data limit reached" while the API answered on every other route (2026-10-29). Vercel taken out of the server's route list and front hosts the same day; XHTTP back on Cloudflare | Done, branch `parsa/foreign-refusal-moves-route`; 824 app tests |
| 2, 60, 61, 94, 95 | One-command server install: `sudo ./install.sh` asks for the domain, the admin, email delivery and the admin password, and does the rest (Docker, keys, certificate, nginx, firewall, Xray, Hysteria2, WireGuard, agent enrolment, protocols, daily encrypted backups); a rerun updates and keeps what is set up; `--restore <backup>` rebuilds a lost server. The first install on a second host found and fixed: the API crashing at first start (agent identity aimed at a read-only mount), `usage` unable to reach the agent, backups missing the state volume and agent.env, the agent unit's ignored start limit, the untracked panel nginx site | Done, branch `parsa/fresh-install-fixes`; on the Tehran VPS 2026-10-26: wiped server to working install unattended in 13 min, rerun safe, a wiped server restored from one backup with identical identity, keys and data (16 min) |
| 60, 61 | Restore drill: newest B2 backup decrypted with the offline key and restored into an empty PostgreSQL; schema, users, devices and servers as live, all 14 secret files match | Done, 2026-10-20 |
| 17, 67 | Android kill switch (Always-on + Block connections without VPN, owner's phone, 0.1.28): app force-stopped 41 s, Wi-Fi to mobile data 36 s, back to Wi-Fi 36 s -- every check blocked, none leaked the phone's own address; app process crashed -- the tunnel kept carrying traffic. A force-stopped app is not restarted by Android until opened again | Done, tested 2026-10-20 |
| 17 | Kill switch on Windows (firewall) and Linux (nftables); Android links to the system's (0.1.20) | Done, archive #264 |
| 10 | Continuous tunnel health: an Xray or Hysteria2 tunnel is asked to carry one small request a minute; three unanswered take it down and reconnect once | Done, archive #275; on Android only while the app is on screen, and checked at once when it is opened again. A reopened app checks through the tunnel's own proxy (archive #334). Each check also asks the tunnel's resolver a DNS question over UDP, the way apps' DNS goes; Android's tun2socks is now hev-socks5-tunnel (as in v2rayNG) in place of badvpn's, restarted if it stops; the probe is a real HTTPS request through the tunnel; UDP shares one connection and QUIC is refused; Automatic favours XHTTP: archive #335. Tunnels always cross the CDN when one is configured: archive #336 |
| 19, 20 | Direct routes: Iranian sites skip the VPN (toggle); websites that skip the VPN (list) (0.1.19) | Done, archive #261 |
| 19, 20, 11 | The app's own API always goes through the tunnel, whatever the routing switches: with Iranian sites direct, the account and device list said "offline" on mobile data while the tunnel worked | Done, archive #369 (0.1.28); on the phone over mobile data 2026-10-20 |
| 19, 20 | Routing switches (sanctioned services only, Iranian sites, websites that skip the VPN) apply at once: a change while connected reconnects the same server; checked on the phone with a subscription config | Done, archive #342 |
| 56, 57, 58, 101 | Privacy page (docs/privacy.md): what is stored and for how long (checked on the live server: no connection logs, no IP addresses, backups expire after 30 days), what the apps send where | Done, archive #353 |
| 71, 101 | License chosen (GPL-3.0-or-later, the owner's choice), third-party license audit (THIRD_PARTY_NOTICES.md: 105 Dart, 81 Python, 53 npm packages and the bundled engines, all compatible), Google's ML Kit replaced by ZXing in the QR scanner, microphone and storage permissions dropped, an Open-source licenses page in Settings | Done, archive #353 |
| 75 | Android battery: no account checks, notification updates or engine counter reads with the screen off; tunnel watch every 30 s out of sight (2 s in front); session timer counted 59-second minutes; the Connect screen shows why the list failed | Done, archive #349; measured on the phone |
| 64 | Desktop helpers write only to admin/root-owned folders (`ProgramData\NebulaVPN\run`, `/run/nebula-vpn-out`); Windows installer locks the install folder to administrators; stale Windows DNS rules swept at connect; Android drops the storage permission the plugin asked for | Done, archive #348; Windows tested on the owner's PC, Linux helper in WSL |
| 53, 64 | Subscriptions: redirects followed by the app, https only and at most three hops (the HTTP client followed one to plain http) | Done, archive #347 |
| 64 | Security: `localhost` walked around the transports' private-address block on Nebula's Xray; host firewall for `nebula-xray` (live) and `UseIPv4` + a name rule in the config | Done, archive #346, archive #352; live 2026-10-17 |
| 60 | Update check while the repository is private: GitHub first, then the API's `/v1/client/release` (`NEBULA_CLIENT_LATEST_VERSION`, set at promotion); signed-in apps only | Done, archive #345; deployed 2026-10-17, seen on the phone |
| 32 | Windows: one copy of the app at a time; launching it again brings the running window back (three tray icons were seen) | Done, archive #343 |
| 11 | ECH keys no longer depend on one resolver: before connecting, the app checks which of UDP 1.1.1.1, 8.8.8.8, 9.9.9.9 answers Cloudflare's HTTPS record, else DNS over HTTPS to 8.8.8.8; all four carried a tunnel from Iran (2026-10-15) | Done, archive #344; on the phone 2026-10-17 |
| 53 | Links and subscriptions in more protocols: VLESS REALITY (with Vision) and raw TCP over TLS, Trojan (TLS; WebSocket, gRPC, XHTTP or TCP), Shadowsocks (AEAD and 2022 ciphers; SIP002 and the old form) and Hysteria2 (Salamander); refused: certificate checks off, plugins, stream ciphers, port hopping, VMess | Done, branch `more-link-protocols`; REALITY+Vision and TCP-TLS+Vision carried traffic against the owner's server, Trojan/Shadowsocks not tried against a live server |
| 68, 74 | Hostile-network scenarios in the app's test run, one per condition, driving the real connect, fallback and protocol test against a network model: UDP blocked, server address blocked, SNI filtered, a blocked protocol held back next time, everything blocked, random loss, offline, blockpage/interception; DNS poisoning, API address blocked, mid-session resets and measured loss are pointed to where already covered | Done, branch `hostile-network-tests`; network-level (netem) lab not built |
| 53 | Free-mode subscriptions the person adds (HTTPS address of a list they trust; none ship with the app): plain or Base64 lists, size and count limits, ETag / Last-Modified, refreshed every ~6 h with jitter and backoff, last good list kept per subscription, duplicates merged by connection settings with every source kept, skipped links counted by protocol | Done, archive #328; every protocol the app reads since archive #333; grouped in Servers with names since archive #335/#338 |
| 47, 70 | Live runtime updates: Xray clients added and removed through Xray's API (restart only as a fallback, or when a removed client's traffic keeps moving), Hysteria2 admits each connection over HTTP and kicks a revoked one, WireGuard applies peers in place | Done, already in production (`NEBULA_XRAY_LIVE_CLIENT_UPDATES=true`) |
| 11 | Tunnels never go through the web-host front (Vercel): arriving through it, WebSocket, gRPC and XHTTP all go through the Cloudflare route with ECH; the front stays an API way in. On the phone 2026-10-14 through Cloudflare: gRPC 89 ms, WebSocket 100-226 ms, XHTTP 108 ms (all three had failed or used Vercel before) | Done, archive #327 (WebSocket and gRPC); XHTTP archive #329 |
| 9, 20 | Connection-quality scoring: each protocol's record on each server is kept on the device (connects that got traffic through, failures that were the protocol's, drops the health check found) and scored with the last protocol test; Automatic tries the best first, holding back a protocol that failed or dropped in the last 30 minutes | Done, archive #325; not per network (the app cannot tell networks apart without a new permission) |
| 22, 77 | Packet-loss test in Diagnostics: 20 UDP DNS queries for random names to 1.1.1.1 (through the tunnel when up), counting unanswered ones; with median delay and jitter, and a line in the copied report | Done, archive #324; on the phone through the tunnel: 0 of 20 lost, 101 ms, varies by 10 ms |
| 64, 68 | SBOM with every client release: `apps/mobile/tool/sbom.py` writes CycloneDX 1.5 from the files that pin each part (pubspec.lock, the Android/Linux/Windows vendoring scripts with their digests, the WireGuard Gradle pin, the services' pyproject.toml, the admin package-lock.json); the release runbook uploads it inside SHA256SUMS.txt | Done, archive #323; first used with the next release |
| 14, 46 | Maintenance mode for app users: a server under maintenance stays in the app's list marked "Under maintenance" (asked for with `include_maintenance`, so older apps do not list it as usable), connecting is refused before anything is registered with a translated message, and the server answers 423 if asked anyway | Done, archive #321; on the phone the list showed "Under maintenance" and Connect gave the message (server in maintenance 65 s, then active again) |
| 108 F49, F50 | Reconciliation, backup and certificate dashboards: covered by reconciliation history and triage (archive #271, archive #272), per-server pending/failed counts (archive #270) and the Security page's backup, certificate and reconciliation rows (archive #319) | Done |
| 42, 48 | Security dashboard (admin "Security" page): PostgreSQL, schema version, Redis, worker (mail queue), usage collector, last backup, reconciliation, API TLS, agent client and node CA certificates, key versions -- each from evidence the API reads itself, Unknown when it cannot; `backup.sh` now records each completed upload in the audit log | Done, archive #319; live: every check reads real evidence, a real backup showed within seconds; it surfaced 42 failed runtime records from Aug 30 - Sep 3, all the e2e-test account's and none on the server (the 15-min prune matched 12 live records to 12 served), closed as revoked with an audit row each (`stale_failed_closed`) |
| 13, 14, 41, 47 | Admin server controls: set a server Active, Maintenance or Disabled from Server health (`POST /v1/admin/vpn-servers/{id}/state`, step-up, audited). Maintenance takes no new connections and leaves the app's list, while its tunnels keep being counted and reconciled (both used to stop on any non-active server) | Done, archive #317; deployed, the route is live and usage counting kept running; not switched on the live server (it is the only one) |
| 39, 46 | Online status per device in the admin user page: Active (tunnel traffic in the last 2 min), Quiet (counters read lately, nothing moved) or Unknown (no recent read), with when traffic last moved, when the counters were last read and when the app last called the API | Done, archive #315; the phone read Quiet while idle and Active within seconds of use |
| 36, 37, 44 | Account expiry: an admin sets or clears the date on the user page (`POST /v1/admin/users/{id}/expiry`, step-up, audited); a sign-in after it says the access has ended (after the password matched) instead of "not accepted"; sign-in, refresh and VPN credentials already stopped at the date | Done, archive #313; tried on the phone with a throwaway account (the message shows; cleared afterwards) |
| 35, 36, 45 | Device limits: an admin sets a user's limit (`POST /v1/admin/users/{id}/device-limit`, step-up, audited); a reinstalled app sends a hardware id (kept only as an HMAC) and gets its old device back instead of a second one | Done, archive #309, archive #311, archive #312; on the phone a reinstall got its old device back at the limit, and a sign-in past it showed the message |
| 32 | Start when you sign in, on Windows (in the tray) and Linux; replaces the desktop's inert "Reconnect after restart" row | Done, archive #276 |
| 79 | Failure messages: name not found, server unreachable, certificate rejected, or protocol blocked (0.1.19) | Done, archive #260 |
| 79 | Failure messages: no traffic on an offline device says offline, not blocked; Linux helper messages shown (0.1.18) | Done, archive #257, archive #256 |
| 4, 28 | Xray 26.9.30 on Windows and Linux; the TLS hello to a `workers.dev` name is written in pieces, which is what gets the free relay through a network that filters those names | Done, archive #282; Linux and Windows run through the deployed relay; Android's engine is too old for it |
| 11 | A second CDN route: `NEBULA_CDN_HOST` takes several names, so a CloudFront name can sit beside the Cloudflare one (Cloudflare's name stalls after the first request from Iran, CloudFront's does not) | Server side done, archive #291; needs an AWS distribution to use |
| 4, 28 | Android engine Xray 26.9.30 (AndroidLibXrayLite, pinned); the Cloudflare route carries the app's tunnel with ECH on the phone | Done, archive #298 |
| 11, 28 | ECH for every tunnel through Cloudflare (CDN route by the server's word, free relays by name); the hello written in pieces is gone | Done, archive #297 |
| 11, 28 | Several built-in backup routes (`API_BACKUP_URL` comma-separated, Vercel first) and a stalled tunnel-config request moves route; Windows honours "Allow local network" (private addresses go out directly) | Done, archive #296 |
| 11 | Pages no longer hang on a throttled route: a GET the route in use has not answered in 2.5 s is also sent down the next one, the first answer wins and its route is used next (the CDN route held every second request 40 s on mobile data) | Done; cold Devices load on LTE 13 s -> about 2.5 s on the phone |
| 10, 68, 74 | End-to-end audit on a real phone and a fresh emulator: every protocol through the UI with the exit address and a 5 MB download checked; 18 bugs found, 13 fixed (WireGuard and raw TCP+TLS said Protected while carrying nothing, a refused VPN permission blamed on the network, no way out of a blocked protocol); connect starts from the saved credential (engine up in under 0.1 s, Protected in 2-4 s); adb harness in apps/mobile/tool/e2e | Done, this branch |
| 11 | The app follows a dead tunnel to the next API route, and on Android checks the tunnel through it rather than around it | Done, archive #293 |
| 11 | A web-host front (Vercel or Netlify) for XHTTP: the server's address and every Cloudflare route are throttled from Iran (measured 2026-10-06, home line and Hamrah-e-Avval), those hosts are not; `NEBULA_FRONT_HOSTS` |  Working on the phone through Vercel (archive #292 server, archive #293 the app); deployed on the owner's Vercel account |
| 28, 63 | Release builds can carry the free relay: `-DefinesFile` on the Windows scripts, `--dart-define-from-file` in the runbook | Done, archive #281 |
| 28 | Free mode in the app: "I don't have a server" on the first page; relays from the build and from pasted links; no account, nothing sent to a server | Done, archive #280; shown in the Windows app; not yet connected through a deployed relay |
| 20 | Fixed: the Add row on "Websites that skip the VPN" did not lay out (0.1.19, 0.1.20) | Done, archive #280 |
| 1, 108 A1-A2 | A second VPN node: `install.sh --join <api> --token <t>` enrols a server into an existing control plane (Add server in the panel makes the token); one node CA; `--configure` changes protocols and ports, firewall and nginx with them; servers can be renamed from Server health | Done, archive #403, archive #404; Tehran joined the German control plane 2026-10-29, phone and Windows connected through both, exits verified |
| 1, 108 A1-A2 | Several servers side by side: a device holds its own WireGuard peer and Xray clients on each server (lookups and live-uniqueness indexes per server, migration 0019); before, a request to the second server reused the first's credential and the app said access had ended. The app drops a server's stale saved credentials and asks afresh | Done, #10, #13, #18; phone with two servers stayed connected through the second (exit through it, 5 MB in 3.8 s), 0.1.33 |
| 10, 11 | Stall check moves real data (128 KB) soon after connecting and after any unanswered reading; protocol test measures download speed after latency on Windows and Linux, 0 Mbit/s ranks as failed | Done, 0.1.33; caught a stalled route in about 20 s on the phone, speed test run on Windows |
| 92, 95 | Published as a fresh public repository with GitHub-hosted CI, Dependabot and secret scanning; history in a private archive | Done 2026-10-30, see `docs/runbooks/going-public.md` |
| 10, 54 | A token refresh refused for a reason that is not the session (429 rate limited, 503 auth store down) no longer reaches the app as the 401 it followed; the access check ends the tunnel on a 401 only once the sign-in has really expired | Done; unit tests for refresh 429/503 and a 401 while still signed in |
| 47, 54 | Rate limits that fit shared addresses: token refresh is limited per token only (a /24 bucket made every device behind one VPN server share 10 refreshes per 15 minutes); sign-in and password reset keep a per-account limit of 10 and get a separate per-/24 limit of 100 (`NEBULA_USER_NETWORK_RATE_LIMIT`) for carrier NAT and VPN exits | Done; unit tests |
| 4, 16 | WireGuard works on a fresh install: `install.sh` turns on IPv4 forwarding, adds NAT on the outgoing interface and a ufw route for `wg0`, and keeps clients off each other, the host, private and Docker ranges and the metadata service; marked, so a rerun changes nothing | Done; rules checked with `iptables-restore --test` against ufw's stock `before.rules`, rerun unchanged, shellcheck |
| 1, 31 | Agent link certificates for one end each: agents' are server-only, the control plane's client-only, so a taken-over server's certificate is refused as a caller ("unsuitable certificate purpose") | Done for new certificates; TLS handshake tests both ways; re-issuing existing ones is in docs/runbooks/deployment.md |
| 5, 11 | Installs no longer look alike to a scanner: `/healthz` and `/readyz` answer 404 from outside (the containers' own checks call the API directly), and a new install picks its own XHTTP and WebSocket paths, gRPC service name, VMess path and Hysteria2 decoy site, written to `agent.env` and nginx; existing installs keep theirs | Done; generated names checked against the agent's settings and the nginx template, shellcheck |
| 42, 47 | New servers get the first server's hardening from `install.sh`: fail2ban with its sshd jail, daily unattended security upgrades, and a 2 GB swapfile where there is no swap and under 4 GB of memory; SSH password login is left to the operator | Done; apt settings checked with `apt-config`, swap condition checked, shellcheck |
| 43, 44 | The backup decryption key no longer stays on the server: `install.sh` shows a new key once and deletes it after the operator confirms it is saved (kept, with a warning, when there is no terminal), `--restore` never stores the key it is given, and the install asks for an off-site destination (B2) or an explicit "this server only" | Done; key flows tested in a scratch /etc/nebula (new with and without a terminal, rerun, older install), shellcheck |
| 42 | Admin panel Content-Security-Policy (per-request nonce, `'strict-dynamic'`, this origin only, `frame-ancestors 'none'`) and Permissions-Policy, set by the panel's `proxy.ts` | Done; built panel served locally: headers present, every script carries the nonce, the sign-in page loads in a browser with no violations |
| 69 | Python dependencies locked with hashes: each service's `requirements.lock` (every package and the build backend, from `make locks`) is all the images and `install.sh`'s agent install from, with `--require-hashes`; CI fails when a lock is out of date | Done; agent installed from its lock into a fresh Ubuntu 24.04 venv and rerun, images built in CI |
| 92 | Roadmap shortened: this file is what comes next plus the status table; the full target (sections 1–109) moved unchanged to `roadmap-sections.md`; ADR 0004 marked accepted in part | Done |
| 95 | CodeQL scanning (GitHub's default setup: Python, TypeScript, workflows) on pull requests, main and weekly; the admin panel's tests enforce a coverage minimum over every source file (53% statements, the level today), in `npm run check` | Done |
| 94 | Project files: SECURITY.md with private vulnerability reporting turned on, CONTRIBUTING.md, issue and pull request templates, CODEOWNERS, CHANGELOG.md | Done |
| 93 | Server upkeep: Xray 26.9.30 on servers, as in the apps (a rerun of `install.sh` upgrades an older one and restarts it; the agent's full config and its live user changes tested on both versions); WireGuard range set at install (`NEBULA_WG_CLIENT_POOL`, default /20) and kept on existing servers; the Windows workflow's upload action pinned and its runs grouped | Done; a fresh install stopped at the WireGuard range under `pipefail` (no `wg0.conf` yet) until the next fix, found by the install test |
| 92 | Docs brought in line with the public repository: pull requests from the private history marked "archive #N" (98 of them), CI described as GitHub-hosted, the nginx files and their install described as they are | Done |
| 28 | Edge relay: the owner's own Cloudflare Worker for people with no server (`services/edge-relay`); no accounts, nothing stored | Done, archive #279, archive #282; deployed 2026-10-02 on a Cloudflare account of its own, private builds carry its link (`FREE_LINKS`), public builds from 0.1.32 do not; relays are dialled like the CDN route (ECH, then the plain and split-hello fallbacks); open: from Iran they stall like every Cloudflare route since ECH was blocked on 2026-10-21 |
| 28 | Link reader for `vless://` (WebSocket, XHTTP, gRPC inside TLS): the first piece of using the app without a Nebula server | Done, archive #278; free mode and Your links use it (archive #333, archive #335); whose Worker serves free users is the owner's decision |
| 77 | Speed test in Diagnostics: download and upload through the tunnel, each cut off at 8 s, at most 28 MB | Done, archive #277 |
| 77, 78 | Diagnostics screen: connection at a glance, WireGuard handshake age, leak test, sanitized report to copy (0.1.18) | Done, archive #255 |
| 60 | SHA-256 manifest with every client release; release runbook | Done, archive #250 |
| 61 | Release signatures: `SHA256SUMS.txt.sig`, OpenSSH file signing against `docs/release-signers`; runbook and verification steps | Done, archive #340; 0.1.24 signed after release; the key backed up encrypted with the others |
| 92, 108 A7 | Documentation brought to current reality | Done, archive #251 |
| 18, 77 | Leak test in Settings › Diagnostics: measured exit, forged-DNS check, resolver network, IPv6 (0.1.17) | Done, archive #252 |
| 4 | Chrome TLS fingerprint on VLESS (0.1.15) | Done, archive #240 |
| 6, 7 | Automatic protocol choice with fallback: last-worked first, up to 4 tries, stops on quota or rate limit (0.1.16) | Done, archive #244 |
| 9 | Protocol list ordered by test result, gRPC last (0.1.14) | Done, archive #238 |
| 10, 18 | Undo an Xray tunnel that carries no traffic (0.1.13) | Done, archive #236 |
| 34 | Temporary credential sweep at startup (0.1.13) | Done, archive #236 |
| 34 | Windows: updates close the running app (session end handled, installer forces) | Done, archive #267 |
| 34 | Windows install wizard, clean uninstall, admin prompt named Nebula VPN (0.1.16) | Done, archive #242, archive #243 |
| 31 | Linux client: Xray, WireGuard and Hysteria2 full-device tunnels; .deb, AppImage and portable .tar.gz | Done, archive #247 (0.1.17) |
| 18 | Linux: DNS may only reach the tunnel's resolvers while it is up (nftables, 0.1.17) | Done, archive #249 |
| 69 | Admin: Next.js 16.3.6 for GHSA-vcvr-r3jv-pc5j | Done, archive #248 |

## 110. Guiding Principles

1. One product externally, modular components internally.
2. Automatic by default, advanced control when requested.
3. Never sacrifice security merely for protocol count.
4. Never sacrifice privacy for convenient analytics.
5. Every credential should be independently revocable.
6. VPN nodes should not own identity/account truth.
7. Public API should never have arbitrary root shell access.
8. Desired state and actual state must be reconciled.
9. "Connected" must mean traffic actually works.
10. A working tunnel should survive temporary control-plane failure.
11. Failure should degrade gracefully.
12. Real-network tests matter as much as unit tests.
13. Every production failure should become a regression test where possible.
14. Protocols are implementation details; users care whether the internet works.
15. Do not claim security/privacy features that have not been verified.
16. Prefer measured truth over configuration assumptions.
17. Avoid browsing/DNS surveillance.
18. Keep management infrastructure unreachable from VPN clients.
19. Sign and verify software distributed to users.
20. Keep documentation synchronized with reality.
21. Reliability and recovery come before feature count.
22. Android + Windows excellence comes before expanding to every platform.
23. Borrow good ideas, not architectural weaknesses.
24. Respect upstream licenses and independently implement restricted ideas.
25. Nebula should eventually replace the need for several separate VPN tools while remaining easier to operate than the collection it replaces.
