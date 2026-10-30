# Nebula VPN — Master Roadmap

The target this project works towards, adopted 2026-10-01. Work is chosen
from it; section 108 gives the recommended order. What is already done is in
the status table below.

Nebula's goal is to become a complete self-hosted VPN platform that combines
the strongest ideas from projects such as WhiteVPN, WhiteDNS, 3x-ui, v2rayN,
WireGuard/Xray ecosystems, and dedicated DNS/privacy tools into one coherent
system.

The objective is not to clone those projects or blindly maximize protocol
count. The target is:

> One control plane, one account/device system, one client experience,
> multiple VPN nodes, multiple connection engines, centralized policy, strong
> security, automatic recovery, privacy-focused DNS, routing, monitoring, and
> administration.

The product should remain modular internally while appearing as one
integrated system externally.

## Status

Updated in the same pull request as the work (section 92).

| Section | Item | State |
| --- | --- | --- |
| 38, 108 F42 | Platform-wide accumulated traffic by engine, exact byte totals and newest collection timestamps in admin | Done, #274 |
| 12, 15, 26, 33, 108 D26 | Nebula's own resolver for Xray clients: AdGuard Home on the server (no filtering, no query log, no statistics, DNS-over-HTTPS upstreams), reached through a reserved address the agent redirects; the API hands it out as `client_dns` | Done, #364; live, seen on the phone (DNS 198.18.0.53) |
| 13, 108 D27-D29 | DNS profiles: an admin gives an account default (the server's own resolver), ads or family, and a device may override it; the API hands Xray clients the matching resolvers; set from the user page in the admin panel (step-up, audited) | Done, #365; deployed (migration 0018), default profile seen on the phone |
| 21, 108 E39 | Routing by address as well as by name: "Websites that skip the VPN" takes IP addresses and ranges (IPv4 and IPv6, never /0), which go direct by an Xray `ip` rule | Done, #366 (0.1.27); on the phone an exempted IP went direct while the rest exited through the server |
| 16, 108 I66 | IPv6 fails closed on every platform: WireGuard claims ::/0, the Android, Windows and Linux Xray tunnels claim it without carrying it, so nothing leaks around the tunnel; carrying IPv6 stays off (mixed families broke YouTube, #352) | Done (verified 2026-10-19) |
| 41, 108 B11 | Admin Xray listener health for enabled Xray nodes: independent state, UTC evidence times, latency and safe errors; WireGuard evidence timestamp | Done, #273 |
| 3, 40, 108 F49 | Reconciliation triage evidence: safe failure reasons, repair-operation correlation, uncertain repair responses recorded as ambiguous | Done, #272 |
| 3, 40, 108 F49 | Reconciliation history: recorded outcomes, timestamps, generations and safe error codes; filter by server, target or outcome; paginated target history | Done, #271 |
| 3, 40, 108 F49 | Server health shows pending provisioning, pending removals and failed runtime records for every server across WireGuard, Xray and Hysteria2 | Done, #270 |
| 69 | API PyJWT 2.15.0 clears the retry PR's dependency-audit blocker (PYSEC-2026-4141) | Done, #268 |
| 3, 106 | Failed WireGuard, Xray and Hysteria2 removals stay pending through repeated failures and retry until confirmed revoked | Done, #268 |
| 11 | Clean Cloudflare address: scan from the device, use the fastest for the CDN route (0.1.20) | Done, #265 |
| 11 | Cloudflare dial fallbacks: a Cloudflare tunnel that carries nothing is redialled plain (clean IP, Chrome, the transport's ALPN), then "F&F" (zero-length TLS hello split, unsafe fingerprint, Python cipher order; reported for Irancell's firewall), then over Cloudflare's IPv6 edge (reported for Hamrah-e-Avval's, only with IPv6); the dial that carried is tried first next time | Done, branch `cdn-dial-fallbacks`; plain dial 1/4 + full 3 MB on a TCI line, F&F/IPv6 untested on their own firewalls |
| 11 | Cloudflare's ECH blocked from Iran (2026-10-21: `cloudflare-ech.com` unanswered, the CDN route carried nothing with or without ECH or a split hello): XHTTP goes through the Vercel front again on every route, WebSocket and gRPC stay on Cloudflare | Done, #378; superseded 2026-10-29: the Vercel front ran out of its free quota and was removed from the routes; Automatic now finds a direct protocol (VLESS TCP+TLS, WireGuard) when Cloudflare stalls |
| 3, 40, 108 F49 | Operator repair controls: "Run reconciliation now" and, on ambiguous or failed history rows, "Check again" for one credential; both run the scheduled passes' own code (repair only safe drift, never widen access), audited, kept apart from the 15-minute sweep by a PostgreSQL advisory lock | Done, #375; live 2026-10-20 (12 Xray clients in sync; a second concurrent sweep skipped) |
| 11 | Shadowsocks-2022 straight to the server (learned from Lantern, which carries Iranian users over it to Alibaba Cloud): the address Iran stalls for TLS carried it at 40-80 Mbit/s from the home line and 31-58 Mbit/s on the phone, 2026-10-22. Agent inbound with live user changes, per-client key from the UUID, `seed-ss2022-protocol`, app reads `protocol`/`method`/`password` | Done, #381; deployed 2026-10-23, released in 0.1.29 (pre-release); fails on MCI mobile data |
| 11 | VLESS Encryption and VMess (raw, WebSocket) straight to the server, no TLS: 53 and 39-47 Mbit/s from the home line, 2026-10-22; like Shadowsocks-2022 they fail on MCI mobile data, where Vercel stays the route. Agent inbounds with live users, `seed-direct-protocols`, the app's VMess outbound and VLESS `encryption` | Done, #381 + #383; deployed 2026-10-23, released in 0.1.29 (pre-release) |
| 44, 45 | External monitoring: a Cloudflare Worker (`services/uptime-monitor`) asks the CDN route an API question every 15 minutes and emails the owner through Cloudflare Email Routing while it fails; a test alert reached the inbox | Done, 2026-10-20; the Vercel front dropped from its targets 2026-10-30 |
| 11 | A route's refusal that is not the API's (no JSON `detail`) counts as a dead route: a disabled Vercel front answered every request "402 Payment required" and the app showed "Data limit reached" while the API answered on every other route (2026-10-29). Vercel taken out of the server's route list and front hosts the same day; XHTTP back on Cloudflare | Done, branch `parsa/foreign-refusal-moves-route`; 824 app tests |
| 2, 60, 61, 94, 95 | One-command server install: `sudo ./install.sh` asks for the domain, the admin, email delivery and the admin password, and does the rest (Docker, keys, certificate, nginx, firewall, Xray, Hysteria2, WireGuard, agent enrolment, protocols, daily encrypted backups); a rerun updates and keeps what is set up; `--restore <backup>` rebuilds a lost server. The first install on a second host found and fixed: the API crashing at first start (agent identity aimed at a read-only mount), `usage` unable to reach the agent, backups missing the state volume and agent.env, the agent unit's ignored start limit, the untracked panel nginx site | Done, branch `parsa/fresh-install-fixes`; on the Tehran VPS 2026-10-26: wiped server to working install unattended in 13 min, rerun safe, a wiped server restored from one backup with identical identity, keys and data (16 min) |
| 60, 61 | Restore drill: newest B2 backup decrypted with the offline key and restored into an empty PostgreSQL; schema, users, devices and servers as live, all 14 secret files match | Done, 2026-10-20 |
| 17, 67 | Android kill switch (Always-on + Block connections without VPN, owner's phone, 0.1.28): app force-stopped 41 s, Wi-Fi to mobile data 36 s, back to Wi-Fi 36 s -- every check blocked, none leaked the phone's own address; app process crashed -- the tunnel kept carrying traffic. A force-stopped app is not restarted by Android until opened again | Done, tested 2026-10-20 |
| 17 | Kill switch on Windows (firewall) and Linux (nftables); Android links to the system's (0.1.20) | Done, #264 |
| 10 | Continuous tunnel health: an Xray or Hysteria2 tunnel is asked to carry one small request a minute; three unanswered take it down and reconnect once | Done, #275; on Android only while the app is on screen, and checked at once when it is opened again. A reopened app checks through the tunnel's own proxy (#334). Each check also asks the tunnel's resolver a DNS question over UDP, the way apps' DNS goes; Android's tun2socks is now hev-socks5-tunnel (as in v2rayNG) in place of badvpn's, restarted if it stops; the probe is a real HTTPS request through the tunnel; UDP shares one connection and QUIC is refused; Automatic favours XHTTP: #335. Tunnels always cross the CDN when one is configured: #336 |
| 19, 20 | Direct routes: Iranian sites skip the VPN (toggle); websites that skip the VPN (list) (0.1.19) | Done, #261 |
| 19, 20, 11 | The app's own API always goes through the tunnel, whatever the routing switches: with Iranian sites direct, the account and device list said "offline" on mobile data while the tunnel worked | Done, #369 (0.1.28); on the phone over mobile data 2026-10-20 |
| 19, 20 | Routing switches (sanctioned services only, Iranian sites, websites that skip the VPN) apply at once: a change while connected reconnects the same server; checked on the phone with a subscription config | Done, #342 |
| 56, 57, 58, 101 | Privacy page (docs/privacy.md): what is stored and for how long (checked on the live server: no connection logs, no IP addresses, backups expire after 30 days), what the apps send where | Done, #353 |
| 71, 101 | License chosen (GPL-3.0-or-later, the owner's choice), third-party license audit (THIRD_PARTY_NOTICES.md: 105 Dart, 81 Python, 53 npm packages and the bundled engines, all compatible), Google's ML Kit replaced by ZXing in the QR scanner, microphone and storage permissions dropped, an Open-source licenses page in Settings | Done, #353 |
| 75 | Android battery: no account checks, notification updates or engine counter reads with the screen off; tunnel watch every 30 s out of sight (2 s in front); session timer counted 59-second minutes; the Connect screen shows why the list failed | Done, #349; measured on the phone |
| 64 | Desktop helpers write only to admin/root-owned folders (`ProgramData\NebulaVPN\run`, `/run/nebula-vpn-out`); Windows installer locks the install folder to administrators; stale Windows DNS rules swept at connect; Android drops the storage permission the plugin asked for | Done, #348; Windows tested on the owner's PC, Linux helper in WSL |
| 53, 64 | Subscriptions: redirects followed by the app, https only and at most three hops (the HTTP client followed one to plain http) | Done, #347 |
| 64 | Security: `localhost` walked around the transports' private-address block on Nebula's Xray; host firewall for `nebula-xray` (live) and `UseIPv4` + a name rule in the config | Done, #346, #352; live 2026-10-17 |
| 60 | Update check while the repository is private: GitHub first, then the API's `/v1/client/release` (`NEBULA_CLIENT_LATEST_VERSION`, set at promotion); signed-in apps only | Done, #345; deployed 2026-10-17, seen on the phone |
| 32 | Windows: one copy of the app at a time; launching it again brings the running window back (three tray icons were seen) | Done, #343 |
| 11 | ECH keys no longer depend on one resolver: before connecting, the app checks which of UDP 1.1.1.1, 8.8.8.8, 9.9.9.9 answers Cloudflare's HTTPS record, else DNS over HTTPS to 8.8.8.8; all four carried a tunnel from Iran (2026-10-15) | Done, #344; on the phone 2026-10-17 |
| 53 | Links and subscriptions in more protocols: VLESS REALITY (with Vision) and raw TCP over TLS, Trojan (TLS; WebSocket, gRPC, XHTTP or TCP), Shadowsocks (AEAD and 2022 ciphers; SIP002 and the old form) and Hysteria2 (Salamander); refused: certificate checks off, plugins, stream ciphers, port hopping, VMess | Done, branch `more-link-protocols`; REALITY+Vision and TCP-TLS+Vision carried traffic against the owner's server, Trojan/Shadowsocks not tried against a live server |
| 68, 74 | Hostile-network scenarios in the app's test run, one per condition, driving the real connect, fallback and protocol test against a network model: UDP blocked, server address blocked, SNI filtered, a blocked protocol held back next time, everything blocked, random loss, offline, blockpage/interception; DNS poisoning, API address blocked, mid-session resets and measured loss are pointed to where already covered | Done, branch `hostile-network-tests`; network-level (netem) lab not built |
| 53 | Free-mode subscriptions the person adds (HTTPS address of a list they trust; none ship with the app): plain or Base64 lists, size and count limits, ETag / Last-Modified, refreshed every ~6 h with jitter and backoff, last good list kept per subscription, duplicates merged by connection settings with every source kept, skipped links counted by protocol | Done, #328; every protocol the app reads since #333; grouped in Servers with names since #335/#338 |
| 47, 70 | Live runtime updates: Xray clients added and removed through Xray's API (restart only as a fallback, or when a removed client's traffic keeps moving), Hysteria2 admits each connection over HTTP and kicks a revoked one, WireGuard applies peers in place | Done, already in production (`NEBULA_XRAY_LIVE_CLIENT_UPDATES=true`) |
| 11 | Tunnels never go through the web-host front (Vercel): arriving through it, WebSocket, gRPC and XHTTP all go through the Cloudflare route with ECH; the front stays an API way in. On the phone 2026-10-14 through Cloudflare: gRPC 89 ms, WebSocket 100-226 ms, XHTTP 108 ms (all three had failed or used Vercel before) | Done, #327 (WebSocket and gRPC); XHTTP #329 |
| 9, 20 | Connection-quality scoring: each protocol's record on each server is kept on the device (connects that got traffic through, failures that were the protocol's, drops the health check found) and scored with the last protocol test; Automatic tries the best first, holding back a protocol that failed or dropped in the last 30 minutes | Done, #325; not per network (the app cannot tell networks apart without a new permission) |
| 22, 77 | Packet-loss test in Diagnostics: 20 UDP DNS queries for random names to 1.1.1.1 (through the tunnel when up), counting unanswered ones; with median delay and jitter, and a line in the copied report | Done, #324; on the phone through the tunnel: 0 of 20 lost, 101 ms, varies by 10 ms |
| 64, 68 | SBOM with every client release: `apps/mobile/tool/sbom.py` writes CycloneDX 1.5 from the files that pin each part (pubspec.lock, the Android/Linux/Windows vendoring scripts with their digests, the WireGuard Gradle pin, the services' pyproject.toml, the admin package-lock.json); the release runbook uploads it inside SHA256SUMS.txt | Done, #323; first used with the next release |
| 14, 46 | Maintenance mode for app users: a server under maintenance stays in the app's list marked "Under maintenance" (asked for with `include_maintenance`, so older apps do not list it as usable), connecting is refused before anything is registered with a translated message, and the server answers 423 if asked anyway | Done, #321; on the phone the list showed "Under maintenance" and Connect gave the message (server in maintenance 65 s, then active again) |
| 108 F49, F50 | Reconciliation, backup and certificate dashboards: covered by reconciliation history and triage (#271, #272), per-server pending/failed counts (#270) and the Security page's backup, certificate and reconciliation rows (#319) | Done |
| 42, 48 | Security dashboard (admin "Security" page): PostgreSQL, schema version, Redis, worker (mail queue), usage collector, last backup, reconciliation, API TLS, agent client and node CA certificates, key versions -- each from evidence the API reads itself, Unknown when it cannot; `backup.sh` now records each completed upload in the audit log | Done, #319; live: every check reads real evidence, a real backup showed within seconds; it surfaced 42 failed runtime records from Aug 30 - Sep 3, all the e2e-test account's and none on the server (the 15-min prune matched 12 live records to 12 served), closed as revoked with an audit row each (`stale_failed_closed`) |
| 13, 14, 41, 47 | Admin server controls: set a server Active, Maintenance or Disabled from Server health (`POST /v1/admin/vpn-servers/{id}/state`, step-up, audited). Maintenance takes no new connections and leaves the app's list, while its tunnels keep being counted and reconciled (both used to stop on any non-active server) | Done, #317; deployed, the route is live and usage counting kept running; not switched on the live server (it is the only one) |
| 39, 46 | Online status per device in the admin user page: Active (tunnel traffic in the last 2 min), Quiet (counters read lately, nothing moved) or Unknown (no recent read), with when traffic last moved, when the counters were last read and when the app last called the API | Done, #315; the phone read Quiet while idle and Active within seconds of use |
| 36, 37, 44 | Account expiry: an admin sets or clears the date on the user page (`POST /v1/admin/users/{id}/expiry`, step-up, audited); a sign-in after it says the access has ended (after the password matched) instead of "not accepted"; sign-in, refresh and VPN credentials already stopped at the date | Done, #313; tried on the phone with a throwaway account (the message shows; cleared afterwards) |
| 35, 36, 45 | Device limits: an admin sets a user's limit (`POST /v1/admin/users/{id}/device-limit`, step-up, audited); a reinstalled app sends a hardware id (kept only as an HMAC) and gets its old device back instead of a second one | Done, #309, #311, #312; on the phone a reinstall got its old device back at the limit, and a sign-in past it showed the message |
| 32 | Start when you sign in, on Windows (in the tray) and Linux; replaces the desktop's inert "Reconnect after restart" row | Done, #276 |
| 79 | Failure messages: name not found, server unreachable, certificate rejected, or protocol blocked (0.1.19) | Done, #260 |
| 79 | Failure messages: no traffic on an offline device says offline, not blocked; Linux helper messages shown (0.1.18) | Done, #257, #256 |
| 4, 28 | Xray 26.9.30 on Windows and Linux; the TLS hello to a `workers.dev` name is written in pieces, which is what gets the free relay through a network that filters those names | Done, #282; Linux and Windows run through the deployed relay; Android's engine is too old for it |
| 11 | A second CDN route: `NEBULA_CDN_HOST` takes several names, so a CloudFront name can sit beside the Cloudflare one (Cloudflare's name stalls after the first request from Iran, CloudFront's does not) | Server side done, #291; needs an AWS distribution to use |
| 4, 28 | Android engine Xray 26.9.30 (AndroidLibXrayLite, pinned); the Cloudflare route carries the app's tunnel with ECH on the phone | Done, #298 |
| 11, 28 | ECH for every tunnel through Cloudflare (CDN route by the server's word, free relays by name); the hello written in pieces is gone | Done, #297 |
| 11, 28 | Several built-in backup routes (`API_BACKUP_URL` comma-separated, Vercel first) and a stalled tunnel-config request moves route; Windows honours "Allow local network" (private addresses go out directly) | Done, #296 |
| 11 | Pages no longer hang on a throttled route: a GET the route in use has not answered in 2.5 s is also sent down the next one, the first answer wins and its route is used next (the CDN route held every second request 40 s on mobile data) | Done; cold Devices load on LTE 13 s -> about 2.5 s on the phone |
| 10, 68, 74 | End-to-end audit on a real phone and a fresh emulator: every protocol through the UI with the exit address and a 5 MB download checked; 18 bugs found, 13 fixed (WireGuard and raw TCP+TLS said Protected while carrying nothing, a refused VPN permission blamed on the network, no way out of a blocked protocol); connect starts from the saved credential (engine up in under 0.1 s, Protected in 2-4 s); adb harness in apps/mobile/tool/e2e | Done, this branch |
| 11 | The app follows a dead tunnel to the next API route, and on Android checks the tunnel through it rather than around it | Done, #293 |
| 11 | A web-host front (Vercel or Netlify) for XHTTP: the server's address and every Cloudflare route are throttled from Iran (measured 2026-10-06, home line and Hamrah-e-Avval), those hosts are not; `NEBULA_FRONT_HOSTS` |  Working on the phone through Vercel (#292 server, #293 the app); deployed on the owner's Vercel account |
| 28, 63 | Release builds can carry the free relay: `-DefinesFile` on the Windows scripts, `--dart-define-from-file` in the runbook | Done, #281 |
| 28 | Free mode in the app: "I don't have a server" on the first page; relays from the build and from pasted links; no account, nothing sent to a server | Done, #280; shown in the Windows app; not yet connected through a deployed relay |
| 20 | Fixed: the Add row on "Websites that skip the VPN" did not lay out (0.1.19, 0.1.20) | Done, #280 |
| 1, 108 A1-A2 | A second VPN node: `install.sh --join <api> --token <t>` enrols a server into an existing control plane (Add server in the panel makes the token); one node CA; `--configure` changes protocols and ports, firewall and nginx with them; servers can be renamed from Server health | Done, #403, #404; Tehran joined the German control plane 2026-10-29, phone and Windows connected through both, exits verified |
| 1, 108 A1-A2 | Several servers side by side: a device holds its own WireGuard peer and Xray clients on each server (lookups and live-uniqueness indexes per server, migration 0019); before, a request to the second server reused the first's credential and the app said access had ended. The app drops a server's stale saved credentials and asks afresh | Done, #10, #13, #18; phone with two servers stayed connected through the second (exit through it, 5 MB in 3.8 s), 0.1.33 |
| 10, 11 | Stall check moves real data (128 KB) soon after connecting and after any unanswered reading; protocol test measures download speed after latency on Windows and Linux, 0 Mbit/s ranks as failed | Done, 0.1.33; caught a stalled route in about 20 s on the phone, speed test run on Windows |
| 92, 95 | Published as a fresh public repository with GitHub-hosted CI, Dependabot and secret scanning; history in a private archive | Done 2026-10-30, see `docs/runbooks/going-public.md` |
| 10, 54 | A token refresh refused for a reason that is not the session (429 rate limited, 503 auth store down) no longer reaches the app as the 401 it followed; the access check ends the tunnel on a 401 only once the sign-in has really expired | Done; unit tests for refresh 429/503 and a 401 while still signed in |
| 47, 54 | Rate limits that fit shared addresses: token refresh is limited per token only (a /24 bucket made every device behind one VPN server share 10 refreshes per 15 minutes); sign-in and password reset keep a per-account limit of 10 and get a separate per-/24 limit of 100 (`NEBULA_USER_NETWORK_RATE_LIMIT`) for carrier NAT and VPN exits | Done; unit tests |
| 4, 16 | WireGuard works on a fresh install: `install.sh` turns on IPv4 forwarding, adds NAT on the outgoing interface and a ufw route for `wg0`, and keeps clients off each other, the host, private and Docker ranges and the metadata service; marked, so a rerun changes nothing | Done; rules checked with `iptables-restore --test` against ufw's stock `before.rules`, rerun unchanged, shellcheck |
| 1, 31 | Agent link certificates for one end each: agents' are server-only, the control plane's client-only, so a taken-over server's certificate is refused as a caller ("unsuitable certificate purpose") | Done for new certificates; TLS handshake tests both ways; re-issuing existing ones is in docs/runbooks/deployment.md |
| 5, 11 | Installs no longer look alike to a scanner: `/healthz` and `/readyz` answer 404 from outside (the containers' own checks call the API directly), and a new install picks its own XHTTP and WebSocket paths, gRPC service name, VMess path and Hysteria2 decoy site, written to `agent.env` and nginx; existing installs keep theirs | Done; generated names checked against the agent's settings and the nginx template, shellcheck |
| 42, 47 | New servers get the first server's hardening from `install.sh`: fail2ban with its sshd jail, daily unattended security upgrades, and a 2 GB swapfile where there is no swap and under 4 GB of memory; SSH password login is left to the operator | Done; apt settings checked with `apt-config`, swap condition checked, shellcheck |
| 28 | Edge relay: the owner's own Cloudflare Worker for people with no server (`services/edge-relay`); no accounts, nothing stored | Done, #279, #282; deployed 2026-10-02 on a Cloudflare account of its own, private builds carry its link (`FREE_LINKS`), public builds from 0.1.32 do not; relays are dialled like the CDN route (ECH, then the plain and split-hello fallbacks); open: from Iran they stall like every Cloudflare route since ECH was blocked on 2026-10-21 |
| 28 | Link reader for `vless://` (WebSocket, XHTTP, gRPC inside TLS): the first piece of using the app without a Nebula server | Done, #278; free mode and Your links use it (#333, #335); whose Worker serves free users is the owner's decision |
| 77 | Speed test in Diagnostics: download and upload through the tunnel, each cut off at 8 s, at most 28 MB | Done, #277 |
| 77, 78 | Diagnostics screen: connection at a glance, WireGuard handshake age, leak test, sanitized report to copy (0.1.18) | Done, #255 |
| 60 | SHA-256 manifest with every client release; release runbook | Done, #250 |
| 61 | Release signatures: `SHA256SUMS.txt.sig`, OpenSSH file signing against `docs/release-signers`; runbook and verification steps | Done, #340; 0.1.24 signed after release; the key backed up encrypted with the others |
| 92, 108 A7 | Documentation brought to current reality | Done, #251 |
| 18, 77 | Leak test in Settings › Diagnostics: measured exit, forged-DNS check, resolver network, IPv6 (0.1.17) | Done, #252 |
| 4 | Chrome TLS fingerprint on VLESS (0.1.15) | Done, #240 |
| 6, 7 | Automatic protocol choice with fallback: last-worked first, up to 4 tries, stops on quota or rate limit (0.1.16) | Done, #244 |
| 9 | Protocol list ordered by test result, gRPC last (0.1.14) | Done, #238 |
| 10, 18 | Undo an Xray tunnel that carries no traffic (0.1.13) | Done, #236 |
| 34 | Temporary credential sweep at startup (0.1.13) | Done, #236 |
| 34 | Windows: updates close the running app (session end handled, installer forces) | Done, #267 |
| 34 | Windows install wizard, clean uninstall, admin prompt named Nebula VPN (0.1.16) | Done, #242, #243 |
| 31 | Linux client: Xray, WireGuard and Hysteria2 full-device tunnels; .deb, AppImage and portable .tar.gz | Done, #247 (0.1.17) |
| 18 | Linux: DNS may only reach the tunnel's resolvers while it is up (nftables, 0.1.17) | Done, #249 |
| 69 | Admin: Next.js 16.3.6 for GHSA-vcvr-r3jv-pc5j | Done, #248 |

## 1. Core Architecture

- Move Nebula onto dedicated production infrastructure.
- Run production on a host of its own, with nothing else on it.
- Separate the control plane from VPN exit nodes.
- Keep PostgreSQL, Redis, API, worker and admin panel on the control plane.
- Keep Xray, WireGuard, Hysteria2, DNS and the VPN Agent on VPN nodes.
- Communicate between control plane and VPN nodes only through the narrow mTLS agent API.
- Never give the public API unrestricted SSH access to VPN nodes.
- Never give the API arbitrary shell execution on VPN nodes.
- Keep VPN Agent operations typed and capability-limited.
- Preserve fixed-argv/no-shell execution.
- Keep VPN runtime configuration separate from account/control-plane logic.
- Make existing tunnels independent from temporary control-plane outages where possible.
- Ensure `API down != existing VPN down`.
- Ensure `Admin down != existing VPN down`.
- Ensure `Database down != immediately killing established tunnels`.
- Maintain last-known-good configuration locally on VPN nodes.
- Keep atomic runtime configuration updates and rollback.
- Add a second real VPN node.
- Validate the architecture against multiple nodes rather than only designing for them.
- Add additional regions after two-node behavior is stable.
- Design for horizontal VPN-node scaling.
- Keep the control plane protocol-neutral.
- Keep connection engines modular so new engines can be added without redesigning accounts/devices.

Target architecture:

```
                         USERS / ADMINS
                              │
                              ▼
                    ┌───────────────────┐
                    │   CONTROL PLANE   │
                    │                   │
                    │ API               │
                    │ Admin             │
                    │ PostgreSQL        │
                    │ Redis             │
                    │ Worker            │
                    │ Policy Engine     │
                    │ Monitoring        │
                    └─────────┬─────────┘
                              │
                             mTLS
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │ Germany-01 │   │ Germany-02 │   │ NL-01      │
       │            │   │            │   │            │
       │ VPN Agent  │   │ VPN Agent  │   │ VPN Agent  │
       │ Xray       │   │ Xray       │   │ Xray       │
       │ WireGuard  │   │ WireGuard  │   │ WireGuard  │
       │ Hysteria2  │   │ Hysteria2  │   │ Hysteria2  │
       │ AdGuard    │   │ AdGuard    │   │ AdGuard    │
       └────────────┘   └────────────┘   └────────────┘
```

## 2. VPN Node Lifecycle

- Add secure one-time VPN-node enrollment.
- Generate short-lived node enrollment tokens.
- Exchange enrollment token for permanent node identity.
- Invalidate enrollment tokens after use.
- Issue unique mTLS identities per node.
- Support agent certificate renewal.
- Support agent certificate rotation without downtime.
- Support node revocation.
- Add node capacity metadata.
- Enforce node capacity rather than treating it as informational.
- Add capacity-aware assignment.
- Add node states `ACTIVE`, `DRAINING`, `MAINTENANCE`, `DISABLED`.
- Prevent new assignments to draining nodes.
- Keep existing sessions alive while draining when safe.
- Support device/profile migration to another node.
- Support graceful node removal.
- Support rolling upgrades.
- Add automatic post-upgrade health validation.
- Roll back upgrades/configuration if validation fails.
- Make a clean Ubuntu VPS reproducibly installable as a Nebula node.
- Minimize manual SSH steps during new-node setup.
- Add unattended/cloud-init installation later.
- Validate actual host state against expected state.

## 3. Desired-State Reconciliation

- Keep PostgreSQL/control plane as the desired-state authority.
- Extend existing WireGuard reconciliation to all connection engines: WireGuard peers, Xray credentials, Xray profiles, Hysteria2 users, DNS policies, node capabilities, firewall state, routing policies, and certificates where appropriate.
- Detect configuration drift.
- Automatically repair safe drift.
- Leave ambiguous drift for operator review.
- Never treat a lost agent response as definite failure.
- Make operations idempotent.
- Preserve operation IDs across retries.
- Surface desired vs actual state in admin UI.

```
Desired: REVOKED
Actual:  ACTIVE
State:   DRIFT
Action:  Retry pending
```

## 4. Supported Connection Engines

**Current / core:** WireGuard, VLESS, XHTTP, WebSocket, gRPC, raw TCP where
useful, TLS, REALITY, Hysteria2.

**Worth considering:** AmneziaWG, Shadowsocks, Trojan, TUIC, AnyTLS, SOCKS
profiles, HTTP proxy profiles.

**Specialized restricted-network engines:**

- Investigate DPI-bypass companion engine.
- Investigate alternative relay/fallback engines.
- Keep experimental transports behind capability flags.
- Do not expose experimental transports as stable before full leak/reliability tests.

Do not add protocols merely for protocol-count parity with 3x-ui/v2rayN.
Every protocol must justify its security review, client implementation,
server implementation, credential lifecycle, monitoring, reconciliation,
upgrade path, failure modes and maintenance burden.

## 5. Protocol Capability Registry

- Maintain a centralized reviewed capability registry.
- Define valid protocol + transport + security combinations.
- Reject free-form unsupported combinations.
- Version capabilities.
- Expose supported and deprecated capabilities to clients.
- Support minimum client versions per capability.
- Support server-specific capability availability.
- Add profile lifecycle states `ACTIVE`, `DEPRECATED`, `DISABLED`.
- Add migration target profile.
- Support profile migration periods.
- Preserve existing profile functionality during a deprecation window.
- Automatically provision replacement credentials before removal.
- Warn clients/admins about deprecated profiles.

## 6. Automatic Protocol Selection

- Add true Automatic mode that chooses the most appropriate protocol.
- Consider latency, handshake success, packet loss, recent failures, throughput, long-transfer reliability, network type, UDP availability, censorship conditions, and protocol history for the current network.
- Avoid relying only on ping.
- Store short-term protocol health.
- Do not store browsing destinations.

Potential fallback chain (the exact ordering should be dynamic rather than
permanently hardcoded):

```
Preferred / best measured
        ↓
XHTTP
        ↓
WebSocket
        ↓
REALITY
        ↓
Hysteria2
        ↓
WireGuard
```

## 7. Automatic Protocol Fallback

- Detect connection failure, handshake failure, successful startup with unusable traffic, transport reset, and repeated packet loss.
- Automatically retry an alternative profile.
- Limit fallback loops.
- Respect manually pinned protocols.
- Explain fallback to the user.
- Preserve diagnostics about the failed attempt.
- Avoid leaking credentials during retries.

## 8. Automatic Server Failover

- Automatically fail over between nodes.
- Respect manually pinned servers.
- Detect server health independently from protocol health.
- Prefer same-region replacement first; fall back to another region if needed.
- Avoid unhealthy/capacity-full nodes.
- Track recent failures.
- Add backoff before retrying a repeatedly failed node.

```
DE-01
  ↓ failure
DE-02
  ↓ failure
NL-01
```

## 9. Connection Quality Scoring

Build a quality score from latency, jitter, packet loss, handshake time,
connect success rate, recent disconnects, throughput, large-transfer
reliability, server load, current capacity, and historical stability on the
current network.

- Do not treat a TCP port opening as a successful VPN test.
- Continue testing traffic through the actual transport.
- Add optional throughput testing; keep heavy bandwidth tests user-triggered.
- Use small safe health probes automatically.

## 10. Continuous Tunnel Health

Borrow the strongest ideas from WhiteVPN Desktop while keeping Nebula's
stronger control-plane model.

- Verify that a tunnel actually carries traffic after connection.
- Periodically verify the tunnel remains usable.
- Detect "Protected/Connected" state with zero usable traffic.
- Tear down false-positive connections.
- Automatically reconnect, switch protocol, or switch server when appropriate.
- Respect manual server/profile pinning.
- Avoid constant high-frequency bandwidth tests; use a small neutral connectivity probe.
- Keep health checks privacy-preserving.

## 11. Clean-IP / CDN Discovery

Borrow the useful concept from WhiteDNS/WhiteVPN.

- Add clean-IP scanning, including Cloudflare/CDN IP scanning where useful.
- Test candidate IP reachability; measure latency, connection reliability and optionally lightweight throughput.
- Cache successful candidates temporarily; expire stale results.
- Allow manually pinned clean IPs and automatic candidate rotation.
- Keep hostname/SNI semantics correct when connecting by IP.
- Ensure TLS verification remains valid; do not disable certificate verification just to make clean-IP routing work.

## 12. DNS Architecture

- Deploy self-hosted AdGuard Home on VPN nodes; stop relying exclusively on public filtering DNS.
- Keep upstream resolvers configurable.
- Support encrypted upstream DNS: DoH, DoT, and standard DNS where needed.
- Add resolver health checking and fallback.
- Keep DNS inside the tunnel; prevent ISP resolver fallback.
- Add DNS leak detection.
- Keep DNS policy independent from VPN protocol where possible.

## 13. DNS Protection Profiles

Default, Privacy, Ads, Ads + trackers, Malware/phishing, Family protection,
Custom, Custom upstream, Custom blocklists, Custom allowlists.

Support per-user, per-device and per-profile DNS policies,
administrator-enforced policies, and user-overridable policies where allowed.

## 14. Multi-Layer Ad Blocking

Keep the current Xray approach and extend it rather than replacing it.

- Layer 1: AdGuard Home → DNS filtering.
- Layer 2: Xray sniffing → HTTP / TLS / QUIC hostname → domain rules → blackhole.
- Layer 3: optional client-side filtering.

- Keep Xray domain blackhole rules.
- Maintain explicit safe blocking lists or generated datasets.
- Avoid breaking required CDN domains.
- Keep DNS and Xray blocking policies synchronized where useful.
- Make protection capabilities visible by protocol.
- Improve Hysteria2 filtering parity.
- Clearly show when a transport only receives DNS-level protection.
- Do not claim YouTube video-ad blocking at network level when it cannot be reliably provided.

## 15. DNS Privacy

- Do not collect long-term DNS query history by default.
- Disable AdGuard query logs or drastically shorten retention.
- Never turn DNS infrastructure into browsing surveillance.
- Expose DNS logging policy in admin.
- Keep aggregate statistics separate from query logs; allow privacy-preserving counters such as number blocked.
- Do not associate domain history with named user accounts.

## 16. IPv6

Either support IPv6 properly or fail closed: IPv6 tunnel addressing, routing,
DNS, AAAA resolution, firewall, management-network blocking, kill switch, leak
detection, split routing, server capability detection and node health
testing. Verify all protocol engines under IPv6 before enabling it globally.
Until then, explicitly prevent unsafe IPv6 fallback.

## 17. Kill Switch

Build real platform-specific kill switches. Test: VPN server disappears;
Xray, WireGuard, Hysteria2, the VPN helper, or the app crashes; the app is
force-killed; Wi-Fi or mobile network disappears; Wi-Fi ↔ mobile; laptop
sleep and wake; Android sleep/doze; battery saver; Windows network adapter
restart; routing table change; DNS resolver failure; control plane
unavailable; VPN node temporarily unavailable.

## 18. Leak Protection

Add automatic diagnostics for public IPv4, public IPv6, DNS, routing, WebRTC
where meaningful, the VPN interface and local routes. Verify the expected exit
IP, expected resolver and VPN server country; compare advertised country with
measured exit country, and prefer measured truth over metadata.

## 19. Split Tunneling

Full VPN mode; per-app inclusion and exclusion; per-domain inclusion and
exclusion; per-IP inclusion and exclusion; CIDR rules; country/geosite-style
groups; sanctions/blocked-services-only mode; direct local-country traffic
mode; custom rules; an explicit LAN access option (exclude or include router,
printer, NAS); validate conflicting rules; display effective routing clearly.

## 20. Routing Presets

Normal users should see simple options: Automatic, Full VPN, Restricted
services only, Exclude local-country services, Selected apps only, Custom.
Advanced users can see actual routing rules.

## 21. Advanced Routing

Borrow the power of 3x-ui/v2rayN without forcing it on normal users: route by
domain, IP/CIDR, protocol, port, application where supported, or
country/category; route to direct, a selected VPN node, a selected protocol, a
proxy outbound, WARP, or blackhole; ordered rules; detect conflicting rules;
preview the effective route; test routing rules before activation.

```
Iranian sites     → Direct
Netflix           → NL-01
Telegram          → DE-02
Games             → Lowest-latency node
Everything else   → DE-01
Ads/trackers      → Blackhole
```

## 22. Load Balancing

Later-stage: balance across multiple VPN nodes (latency-, load-, health-aware,
weighted), fallback groups, balancer-to-balancer fallback, avoid flapping,
sticky policy where required. Do not implement before normal failover is
reliable.

## 23. Outbound Chaining

Advanced mode: VPN node → another VPN node / SOCKS / HTTP proxy / WARP /
custom upstream proxy; chained proxy health validation; prevent routing
loops; clearly show increased latency/security tradeoffs.

## 24. Client Modes

Primary modes: Automatic, Fast, Reliable, Restricted Network, Manual /
Advanced. Automatic should hide implementation details; Advanced should
expose them.

## 25. Server Picker

Show region, country, city, hostname/friendly name, measured exit country,
latency, packet loss, quality score, load, capacity, protocol health and
maintenance status. Support favorite, pinned and automatic server selection,
search/filter, and country and protocol filters.

## 26. Protocol Picker

Automatic mode, manual mode, latency result, throughput result, last success,
last failure, stability indicator, availability, filtering capability, UDP
capability, current network compatibility.

## 27. Server Workbench

Borrow this strongly from WhiteVPN/v2rayN: test all servers and all
protocols; latency, reachability, throughput, packet-loss and long-transfer
tests; sort by latency, throughput, reliability, quality or country; save
results temporarily; avoid test storms against the control plane.

## 28. Subscription and Import Compatibility

Nebula should not require every advanced user to use only Nebula-generated
profiles. Support optional import of VLESS URLs, Hysteria2 URLs, WireGuard
configs, Trojan URLs, Shadowsocks URLs, VMess URLs if VMess is supported,
SOCKS and HTTP proxy profiles, Clash/Mihomo YAML, Xray JSON, subscription
URLs and plain Base64 link lists. Maintain strict validation. Keep external
profiles clearly separated from centrally managed Nebula profiles.

## 29. Subscription Management

Custom subscriptions; automatic refresh with a configurable interval;
last-valid offline cache; source fallback; manual refresh; edit and delete;
subscription health; import preview; duplicate detection; fail safely on
malformed input.

## 30. Profile Sharing

For externally shareable profiles where policy permits: QR code, share link,
config export, selected-profile export, short-lived export links,
authentication where possible. Do not replace Nebula's per-device
authenticated credential model with permanent public subscription URLs.

## 31. Client Platforms

Priority: Android, Windows. Then macOS and Linux. Later, if justified: iOS.
Quality on two platforms is more important than mediocre support on five.

## 32. Client Runtime Modes

Full TUN VPN, local SOCKS proxy, local HTTP proxy, system proxy mode,
background/tray operation, start at boot, auto-connect, reconnect after sleep
and after network transition, restore previous connection safely.

## 33. Android Networking

Test and support Android 8+, VpnService, app inclusion/exclusion, doze,
battery saver, foreground service rules, network transitions, Wi-Fi/mobile
handoff, captive portals, process death, reboot, and Always-on / lockdown VPN
compatibility where practical.

## 34. Windows Networking

Robust TUN/Wintun handling; administrator elevation only when genuinely
needed; safe helper process design; safe process cleanup; clean temporary
credential files; startup cleanup; resume from sleep; interface transitions;
tray operation; system proxy mode; installer; portable build if useful;
Windows ARM64 later if justified.

## 35. Device Management

User-friendly device names, platform, app version, creation time, last
connection, current server, profile and session; revoke, disable and rename
devices; enforce and display the device limit; independently revoke protocol
credentials.

```
Parsa's OnePlus
Android
Last seen: 2 min ago
Server: DE-01
Protocol: XHTTP
Status: Connected
```

## 36. User Access Policies

Per user: allowed protocols, profiles and servers; device limit; account
expiry; traffic quota and reset interval; DNS policy; routing policy;
bandwidth limits later if needed.

## 37. Traffic Quotas

Borrow the useful management concepts from 3x-ui: total usage quota,
upload/download accounting, renewal/reset periods, expiry date, scheduled and
admin resets, user-visible remaining quota, warnings before exhaustion, safe
disabling of provisioning/access on exhaustion. Keep traffic accounting
aggregate; never record destination history.

## 38. Usage Statistics

Privacy-preserving per-user, per-device, per-server and per-protocol traffic;
active devices and tunnels; total tunnel uptime; connection attempts and
failures. Avoid destination sites, DNS history, URL history and packet
contents.

## 39. Online Status

Active/inactive device status, recent handshake, recent authenticated tunnel
activity, server-visible health; avoid claiming precise online state when
evidence is stale; expose the timestamp of the last evidence.

## 40. Admin Dashboard

Overview, Users, Devices, Sessions, Servers, Protocols, Profiles,
Permissions, Assignments, Routing, DNS, Usage, Health, Reconciliation,
Backups, Certificates, Security, Audit Log, Email Deliveries, Settings.

## 41. Admin Server Management

Add, enroll, disable, drain, put into maintenance, and safely delete servers;
show agent health and version, supported capabilities, active devices,
traffic, CPU, RAM, disk, bandwidth, protocol health and reconciliation state.

## 42. Admin Security Status

One factual security dashboard:

```
API                       Healthy
PostgreSQL                Healthy
Redis                     Healthy
Worker                    Healthy

Last backup               6h ago
Backup status             OK

TLS expires               63 days
Agent certificates        Valid
JWT key                   Current
MFA key                   Current

Security scan             Passing
Container scan            Passing
Secret scan               Passing

Reconciliation            Clean
Database schema           Current
```

## 43. Monitoring

Privacy-preserving metrics for API, database, Redis, worker, VPN agent, Xray,
WireGuard, Hysteria and DNS health; CPU, RAM, disk, network throughput,
packet loss; active tunnels; connection success, failure and
per-protocol failure rates; reconciliation errors; backup state; certificate
lifetime.

## 44. External Monitoring

Monitor the control plane and VPN nodes from outside the VPS; detect complete
host outage, DNS failure, TLS failure and regional reachability issues; keep
probes non-sensitive.

## 45. Alerts

Alert on: node or control plane unreachable; database, Redis, worker, VPN
Agent, Xray, WireGuard, Hysteria or DNS unhealthy; reconciliation failure;
disk > 80% and > 90%; capacity nearly exhausted; backup failed or stale; TLS
or agent certificate expiry approaching; unusual connection failure spike.
Possible integrations later: email, Telegram, Discord, generic webhooks.

## 46. Maintenance Mode

Global, node, and protocol/profile maintenance modes; block new
provisioning; preserve existing tunnels when safe; show maintenance state and
expected availability to clients.

## 47. Live Runtime Updates

Where safe: add and revoke Xray clients without restarting all of Xray or
dropping unrelated connections; update routing rules and allowed profile
state safely; minimize disruptive full-core restarts; validate live updates
before committing desired state; fall back to atomic restart when live
mutation is unsafe.

## 48. Firewall Security

Declarative firewall policy; automatically verify actual firewall state;
limit agent access to expected networks; restrict database/Redis to internal
networks; restrict admin/control-plane ports; restrict management interfaces
from VPN clients; regression-test firewall behavior; keep personal/internal
services unreachable from VPN users.

## 49. Internal Network Isolation

Permanent tests must ensure connected VPN users cannot reach localhost
services, control-plane private addresses, PostgreSQL, Redis, Docker
networks, the Xray management API, the VPN Agent management interface,
internal metrics endpoints, admin-only services, or host-only services unless
deliberately allowed. Repeat for IPv4 and IPv6.

## 50. Authentication

Preserve and strengthen: Argon2id passwords, Ed25519 access JWTs, rotating
opaque refresh tokens, refresh-family reuse detection, per-device sessions,
immediate revocation, neutral account recovery responses, password reset,
activation flow, session expiration, rate limiting, lockout, account
enumeration resistance.

## 51. Administrator Authentication

Keep a separate admin identity realm, password + TOTP, recovery codes,
step-up MFA, HttpOnly SameSite sessions, CSRF protection, origin checks,
session expiration, lockout, rate limiting, admin session visibility and
remote session revocation. Add WebAuthn/passkeys and hardware security key
support where possible.

## 52. Admin Roles

When multiple administrators become necessary: Owner, Security Admin,
Operator, Support, Read Only, with granular permissions rather than one giant
admin role.

## 53. Key Management

Manage JWT signing keys, token peppers, MFA encryption keys, Xray credential
encryption keys, the agent CA and certificates, TLS certificates and backup
encryption keys. Track current and previous accepted versions, creation time,
rotation status and expiry.

## 54. Safe Key Rotation

```
Generate new
    ↓
Publish verification/decryption material
    ↓
Switch active key
    ↓
Verify
    ↓
Keep old during migration
    ↓
Retire old
```

Automate safe stages, support rollback, detect incomplete rotations, and
prevent accidental loss of required previous keys.

## 55. Certificate Lifecycle

Monitor TLS and mTLS expiry; automate renewals safely; alert well before
expiry; support overlapping old/new certificates; verify a new certificate
before switching; support node certificate revocation.

## 56. Privacy Model

A dedicated privacy document explaining what the control plane stores, what
VPN nodes store, what DNS servers and administrators see, what clients send,
what telemetry exists, what is never collected, retention periods, IP
metadata, traffic usage and audit retention, and the deletion process.

## 57. Privacy Principles

Never collect browsing history, packet contents, destination URLs, complete
DNS history, private keys, plaintext credentials, plaintext reset/activation
tokens, client configs in logs, or Xray credentials in logs. Keep
operational metadata minimal.

## 58. Data Retention

Define requester-data, audit, auth-event, email-event, usage-data,
server-health and reconciliation retention; automatically prune expired data;
test pruning regularly.

## 59. Account Deletion

User- and admin-triggered deletion that revokes active sessions, WireGuard
peers, Xray and Hysteria credentials, deletes or anonymizes retained metadata
according to policy, and preserves legally/security-required audit records
only as defined.

## 60. Backup System

Complete the existing design: deploy the real Backblaze B2 backup; configure
the age public key and keep the private key offline; daily PostgreSQL
backups; back up required secrets; encrypt before upload; 30-day lifecycle
retention; monitor backup success; alert on stale backups; test backup
integrity.

## 61. Disaster Recovery

Document recovery from database corruption, Redis loss, control-plane VPS
loss, VPN node loss, secret-file loss, JWT key loss, MFA key loss, agent
certificate loss, broken deployment, failed migration, and compromised node.

## 62. Restore Testing

Quarterly: provision a clean host; restore PostgreSQL, secrets and deployment
identity; verify migration state, users, devices, assignments, encrypted
credentials, node reconnection, admin login and new VPN provisioning. A
backup is not considered proven until restored successfully.

## 63. Release Pipeline

Deterministic/repeatable builds where possible; tagged releases built through
CI; a release manifest with SHA-256 hashes; cryptographic signatures; signed
update metadata; source revision in artifacts; exact dependency versions;
binary component hashes.

## 64. Windows Release Security

Signed installer and executable; verify update signatures and the release
manifest; prevent arbitrary update URL execution; eventually obtain a trusted
code-signing identity.

## 65. Android Release Security

Stable signing key with secure custody and a reproducible signing process;
verify update metadata; prevent downgrade attacks where appropriate; publish
release checksums/signatures.

## 66. Update Channels

Internal, beta and stable, with channel-specific release metadata, safe
automatic update, user-controlled update behavior, rollback, staged rollout
later, and minimum supported version enforcement only when required.

## 67. Release Authenticity

Borrow the security principle used by v2rayN/3x-ui: publish SHA-256 and a
signature; the client and updater verify hash/signature and abort on
mismatch; protect against compromised mirrors/CDNs; do not trust transport
TLS alone for application updates.

## 68. SBOM and Supply Chain

Generate SBOMs for releases recording Python, npm and Dart packages, native
binaries, and the Xray, Hysteria, WireGuard and plugin versions. Add
provenance/attestation later.

## 69. Dependency Security

Keep Dependabot, Gitleaks, Trivy, container scanning, strict lock files and
pinned Actions. Add automated compatibility tests and a real connection test
for protocol-core upgrades; prevent blind auto-merge of protocol-core
updates; verify upstream archive hashes; track native binary hashes.

## 70. Patched Third-Party Code

Minimize patches and document why each exists; pin the exact upstream
revision; automatically verify each patch applies and fail the build if not;
test patched behavior directly; periodically check whether upstream fixed the
issue; remove patches when no longer needed.

## 71. Licensing

Before public distribution: audit every dependency license (Xray, Hysteria,
WireGuard libraries, Flutter/native plugins, imported code, GPL
dependencies); keep THIRD_PARTY_NOTICES; never copy code from
source-available projects that prohibit reuse; independently implement ideas
rather than copying restricted source; decide Nebula's own license before
public release.

## 72. Automated Testing

Maintain very strong unit tests, branch coverage, linting, formatting, static
typing, migration tests, PostgreSQL and Redis integration tests, concurrency
tests, container tests and native WireGuard tests.

## 73. Real End-to-End Testing

Android → actual VPS; Windows → actual VPS; real WireGuard, VLESS, XHTTP,
WebSocket, gRPC, REALITY and Hysteria tunnels; real DNS, split routing, ad
blocking, server failover and protocol fallback.

## 74. Hostile Network Test Lab

UDP completely blocked or heavily throttled; QUIC blocked; TCP reset; long
connections reset; random packet loss; severe jitter; high latency; DNS
poisoning; UDP/53 or TCP/53 blocked; IPv6 DNS broken; transparent DNS
interception; server IP blocked; SNI filtering; selected CDN IP blocked;
local censorship blockpage injection.

## 75. Network Transition Testing

Android: Wi-Fi → LTE, LTE → Wi-Fi, airplane mode, phone sleep, doze,
background restrictions, captive portal. Windows: Wi-Fi disconnect, Ethernet
connect, sleep, resume, adapter reset, network switch, VPN process crash.

## 76. Chaos Testing

Kill the API during provisioning or after agent success before DB finalize;
drop agent responses; restart PostgreSQL during an operation, Redis during
refresh rotation, the worker during email delivery; kill Xray during a config
update; lose network during reconciliation; fill disk temporarily; corrupt
temporary configuration; fail backup upload; fail certificate renewal.

## 77. Client Diagnostics

A dedicated diagnostics screen:

```
VPN              Connected
Server           Germany 01
Protocol         XHTTP
Exit IP          91.x.x.x
Exit Country     Germany
DNS              Protected
DNS Resolver     Nebula AdGuard
DNS Leak         None
IPv6 Leak        None
Packet Loss      0.3%
Handshake        184 ms
Download         26 Mbps
Upload           9 Mbps
Ad Blocking      Enabled
Kill Switch      Enabled
```

## 78. Diagnostic Export

Sanitized export of app version, OS version, tunnel type, anonymized server
identifier if needed, protocol state, failure class and recent local logs.
Never export private keys, raw auth or refresh tokens, passwords, Xray
UUIDs/passwords, full client configs, visited domains or DNS history.

## 79. Failure Messages

Differentiate: internet unavailable; DNS unavailable; server unreachable;
protocol blocked; TLS verification failure; authentication rejected;
handshake timeout; tunnel started but no traffic; server stopped responding;
local VPN adapter failure; permission/elevation failure; configuration
invalid; control plane unavailable. Avoid generic "Connection failed"
whenever a useful classification exists.

## 80. Client Localization

Keep and expand English, Persian (correct RTL), German, French, Spanish,
Arabic, Russian, Turkish, Chinese, and others based on actual demand; keep
technical terms consistent; do not expose untranslated protocol internals in
normal mode.

## 81. Client Design

System, light and dark themes; reduced-motion support; accessible labels;
keyboard navigation on desktop; responsive layouts; clear offline,
maintenance, expired-account and restricted-access states.

## 82. Simple User Experience

The main screen should eventually be close to:

```
        NEBULA

      Protected

      Germany
      Automatic

   [ Disconnect ]
```

Normal users should not need to understand VLESS, gRPC, XHTTP, REALITY,
Hysteria, MTU, mux or fragmentation. Those belong under Advanced.

## 83. Advanced User Experience

Advanced users may configure server, protocol, transport, DNS, routing mode,
split tunnel, fragmentation, mux, IPv6 preference, proxy mode, local ports,
logging level and imported profiles.

## 84. Logging

Fault-only by default; optional diagnostic level; a clear warning when
destination logging is enabled; automatic expiration of verbose logs; redact
secrets, credentials and tokens; avoid full config dumps.

## 85. Crash Reporting

If introduced: opt-out/consent where appropriate; scrub tokens, credentials,
VPN config, domain history and unnecessary private IP data; never upload raw
tunnel logs automatically.

## 86. API Versioning and Capability Negotiation

Version API contracts; expose client/server compatibility and the capability
list; allow old clients to operate safely; reject unsupported behavior
clearly; test old client → new server and new client → older supported
server; prevent silent semantic changes.

## 87. Backward Compatibility

Maintain tests for at least recent releases: previous and current stable
Android and Windows clients against the current API and server capabilities.

## 88. Profile Migration

Migration target, deprecation date, warning period, new credential
provisioning, client migration prompt, automatic migration when safe, old
credential revocation after the deadline, operator override.

## 89. Audit System

Append-oriented audit logs for authentication, admin login, MFA, user
approval and rejection, device creation and revocation, permission and
assignment changes, node enrollment and removal, profile changes,
reconciliation, key rotation, backup operations and administrative security
actions.

## 90. Tamper-Resistant Audit Export

Later: periodic signed audit snapshots to external storage, hash chains or
signed batches, export integrity verification, and preventing ordinary admin
action from silently rewriting history.

## 91. Documentation

Make documentation match reality: README, architecture, threat model,
current capabilities, supported platforms and protocols, deployment guide,
VPN-node guide, disaster recovery, backup restore, key rotation, release
process, privacy model, troubleshooting, contributor guide.

## 92. Documentation Drift

Choose one canonical current-status file; avoid duplicating status across
files; generate the app version, supported protocol list and capability
tables where possible; validate documentation references in CI; update the
roadmap with completed items in the same PR.

## 93. Architecture Diagrams

Control plane, VPN node, authentication, provisioning, WireGuard lifecycle,
Xray lifecycle, DNS path, ad blocking, routing, multi-node failover, key
management, backups, trust boundaries.

## 94. Installation Experience

For self-hosters: a prerequisites checker; guided and unattended install;
generated random initial secrets with secure placement; validation of ports,
DNS, firewall, TLS and system resources; a post-install health check and a
clear result. Eventually `curl ... | nebula-install`, only if it can be done
securely and transparently; prefer signed downloaded installers over blind
remote shell execution.

## 95. Self-Hosting Modes

Single-host personal install; separated control plane + VPN node; multi-node
install; external PostgreSQL; external Redis if justified; managed DNS;
self-hosted AdGuard. Keep single-host mode available for small personal
setups even after the distributed architecture exists.

## 96. Resource Limits

CPU and memory limits; disk monitoring; log rotation; PostgreSQL and Redis
storage monitoring; node bandwidth monitoring; application queue limits;
request body limits; timeouts; connection limits.

## 97. Database

Continue PostgreSQL as the primary database with explicit Alembic
migrations, an application role without DDL, a migrator role, schema-head
readiness checks, concurrency tests, restrictive foreign keys and append-only
audit protections. Add migration recovery drills, production migration
verification, index/performance monitoring, and capacity forecasting later.

## 98. Redis

Private/internal only; authentication; persistence; session TTL; safe
failure behavior; test restart and unavailability; define which operations
fail closed; avoid making established VPN traffic depend on Redis.

## 99. Email

Continue the durable outbox, retry/backoff, neutral account emails, Resend
support, SMTP abstraction and delivery observability. Add provider health,
alerts on repeated delivery failure, and safe provider fallback later if
necessary.

## 100. User Self-Service

See account status, devices, sessions, usage, expiration and quota; rename
and revoke own devices; revoke sessions; change and reset password; manage
optional DNS preferences; export sanitized diagnostics.

## 101. Public Release Readiness

Before public distribution: dedicated infrastructure; second node tested;
backup deployed and restore tested; signing implemented; privacy policy and
data retention complete; license chosen; third-party license audit complete;
update mechanism secured; kill switch, DNS leaks and IPv6 posture tested;
real-device E2E passing; disaster-recovery runbook tested; external security
review if practical.

## 102. What to Borrow from WhiteVPN

One-tap simple UX; built-in Automatic behavior; manual server selection;
latency and download-speed tests; automatic connection recovery; subscription
support with offline cache; per-app split tunnel; global/full VPN mode;
local-country bypass mode; clean-IP scanning; LAN sharing concepts if
appropriate; DoH/DoT; real exit-country verification; server workbench. Do
not copy code unless licensing explicitly permits and the architecture
benefits from it.

## 103. What to Borrow from WhiteDNS

Think beyond standard VPN protocols; specialized censorship-resistance engines;
resolver profiles; connection progress visibility; traffic statistics; split
routing; engine abstraction; clean-IP ecosystem ideas. WhiteDNS
source-available components that prohibit reuse must only inspire
independently implemented behavior.

## 104. What to Borrow from 3x-ui

Rich server administration; per-user quotas, expiry and device/IP limits;
usage resets; live user status; traffic accounting; multi-node management;
node cloning concepts where appropriate; routing rules; outbound chaining;
load balancers; fallback groups; WARP upstream; live Xray updates; unattended
installation; API documentation; remote monitoring integrations. Do not copy
3x-ui's complexity into the normal client UX.

## 105. What to Borrow from v2rayN

Desktop power-user flexibility; broad profile import and subscription
compatibility; advanced TUN settings; configurable routing; multi-core
abstraction concepts; Windows/Linux/macOS packaging maturity; system proxy
behavior; signed release verification; power-user diagnostics. Keep these
behind Advanced mode.

## 106. What Nebula Should Keep as Its Advantage

Do not lose these while chasing feature parity: centralized account and
device systems; per-device credentials; independent revocation; per-user
protocol permissions and server assignments; a proper control-plane
database; the typed VPN Agent API; mTLS; no arbitrary root shell from the
public API; desired-state reconciliation; strong token lifecycle; admin MFA;
CSRF protection; audit events; privacy-focused logging; real production
testing; real failure-driven regression testing. These are what make Nebula
more than another VPN panel.

## 107. Features to Avoid Rushing

Payments; subscriptions/billing; affiliate systems; dozens of protocols; iOS
before Android/Windows quality is strong; macOS before Windows client
reliability is strong; huge analytics platforms; invasive telemetry; AI
features without a real use case. Reliability first.

## 108. Recommended Development Order

**Phase A — Production Foundations.** 1. Dedicated Nebula production
VPS/infrastructure. 2. Separate control plane and VPN node. 3. Deploy
backups for real. 4. Perform restore drill. 5. Add external monitoring.
6. Add alerts. 7. Update documentation to current reality.

**Phase B — Multi-Node.** 8. Add second VPN node. 9. Secure node enrollment.
10. Node certificate lifecycle. 11. Node health monitoring. 12. Capacity-aware
assignments. 13. Node draining. 14. Maintenance mode. 15. Node migration.
16. Automatic server failover.

**Phase C — Smart Client.** 17. Automatic protocol selection. 18. Automatic
protocol fallback. 19. Continuous tunnel health. 20. Connection-quality
scoring. 21. Throughput testing. 22. Packet-loss testing. 23. Clean-IP
scanning. 24. Diagnostics screen. 25. Better failure explanations.

**Phase D — DNS and Privacy.** 26. Self-hosted AdGuard Home. 27. DNS policy
system. 28. Per-user DNS. 29. Per-device DNS. 30. Preserve Xray hostname
blackhole. 31. Improve Hysteria filtering parity. 32. DNS leak detection.
33. DNS privacy/retention controls.

**Phase E — Routing.** 34. Split tunneling. 35. Per-app rules. 36. Per-domain
rules. 37. LAN access control. 38. Routing presets. 39. Advanced routing.
40. Outbound chaining later. 41. Load balancing later.

**Phase F — Administration.** 42. Traffic statistics. 43. User quotas.
44. Expiry. 45. Device limits. 46. Online status. 47. Admin server controls.
48. Security dashboard. 49. Reconciliation dashboard. 50. Backup/certificate
dashboards.

**Phase G — Client Ecosystem.** 51. Mature Android. 52. Mature Windows.
53. Subscription/import compatibility. 54. Profile workbench. 55. macOS.
56. Linux. 57. iOS only when justified.

**Phase H — Distribution Security.** 58. Windows code signing. 59. Android
release signing workflow. 60. SHA-256 release manifests. 61. Cryptographic
release signatures. 62. Signed updater metadata. 63. Update channels.
64. SBOM. 65. Provenance/attestation.

**Phase I — Advanced Resilience.** 66. IPv6. 67. Full kill-switch matrix.
68. Hostile-network CI/lab tests. 69. Chaos testing. 70. Live runtime
configuration. 71. Rolling upgrades. 72. Multi-region balancing.
73. Alternative restricted-network transports.

## 109. Definition of the Final Product

The intended result is not "3x-ui clone + v2rayN clone + WhiteVPN clone +
AdGuard". The target is:

```
                         NEBULA
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
       CLIENTS         CONTROL PLANE       VPN FLEET
          │                 │                 │
 Android/Windows       Accounts          WireGuard
 macOS/Linux           Devices           Xray
                       Permissions       Hysteria2
 Automatic Mode        Assignments       DNS
 Advanced Mode         Policies          Future Engines
 Diagnostics           Routing
                       Monitoring
                       Reconciliation
                       Backups
                       Security
```

The normal user experience should eventually be:

```
Install Nebula
      ↓
Sign in
      ↓
Press Connect
      ↓
Nebula automatically chooses:
    server
    protocol
    routing
    DNS
    failover
      ↓
Protected
```

The advanced user should still be able to control nearly everything. The
administrator should be able to operate the entire VPN fleet from one
system.

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
