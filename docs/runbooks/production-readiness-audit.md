# Production-readiness audit — findings and status

Tracks every finding from the 2026-09-17 production-readiness audit (source
review plus read-only inspection of the live VPS), in severity order, so
what's fixed and what's still open is in one place instead of a chat
transcript. Update this file's status column in the same PR that fixes or
knowingly defers an item — don't let it drift from what's actually shipped.

Legend: ✅ fixed, merged, and deployed to production · 🟡 fixed, not yet
merged or deployed · ⬜ not started · 🔒 needs the operator (system/security
setting this assistant doesn't change unilaterally)

A separate bug found and fixed the same day, unrelated to this audit --
Hysteria2 reporting the tunnel connected before it actually was -- is
tracked in its own PR, #199, not in this table.

## Critical

| # | Finding | Status | Where |
|---|---|---|---|
| C-1 | A connected VPN user could reach the server's own loopback, the Docker network (Postgres/Redis), and Xray's unauthenticated HandlerService, because the `freedom`/`direct` outbounds carried no destination ACL | ✅ | `services/vpn-agent/src/nebula_agent/drivers/egress.py` (shared blocklist), wired into `xray_config_store.py` and `hysteria_config_store.py`. [#198](https://github.com/Parsabrg/vpn/pull/198), merged and deployed 2026-09-17. **Confirmed closed live**: from the connected phone, a request to the Docker network's Postgres address now resets in 0.22s (Xray's blackhole outbound, before any real dial) vs. a 6s hang with no reset for a genuinely-unreachable-but-not-blocked external port |
| C-1b | The C-1 block could be walked around **by name**: `localhost` has no public answer, so the address rule never saw an address, and `freedom` then asked the host's resolver, which answers 127.0.0.1. Measured on the production Xray (26.3.27) on 2026-10-15: a client reached a loopback-only port as `localhost:<port>`; as the real `nebula-xray` user, another local Xray's API (127.0.0.1:10085), the API (8000) and admin (3000) were open. The host-firewall layer described under C-1 had never been put in place | ✅ | Host: ufw rules refusing new connections from `nebula-xray` to the blocked ranges, before ufw's loopback accept (deployment.md, "Host firewall for the transports"), live 2026-10-15. Config: `freedom` resolves with Xray's public resolvers (`UseIP`) and `localhost` is refused by name (`xray_config_store.py`). Hysteria2 tested the same way and was not affected (its resolver serves its outbound too) |

## High

| # | Finding | Status | Where |
|---|---|---|---|
| H-1 | SSH allows password auth + root login; no fail2ban; 6,709 failed root attempts / 24h from 188 IPs; `reza` is a stale sudo+password account | ✅ | Applied on the VPS 2026-09-17: fail2ban installed and enabled; `PasswordAuthentication no`; `PermitRootLogin prohibit-password`; `reza` password locked. Key-based login re-verified with `ssh -o BatchMode=yes` after the reload, which fails outright rather than prompting, so there was no lockout window. **The password setting lives in `/etc/ssh/sshd_config.d/50-cloud-init.conf`, not `sshd_config`** — that drop-in is included at line 12, before the main file's own (commented) directive, and OpenSSH keeps the first value it sees, so editing only `sshd_config` is a silent no-op. Confirm with `sshd -T`, never by reading one file. **Accounts and passwords on this host are off-limits from here on, by the operator's instruction** — the `reza` lock is the last such change |
| H-2 | Services that are not Nebula's share the production host and root | 🔒 | Each runs with a systemd drop-in (`InaccessiblePaths=-/etc/nebula -/var/lib/docker`), verified through `/proc/<pid>/root`: they cannot read Nebula's keys or the database files, while `nebula-vpn-agent` still can. This narrows the path; a real root exploit can leave a namespace. A host of Nebula's own removes it, and is worth doing before going public |
| H-3 | ~~IPv6 traffic bypasses the tunnel~~ — **corrected on re-check**: phone's `Routes:` show `::/0 -> tun0`, IPv6 *is* captured. Real problem found instead: an IPv6 resolver in the DNS list was routing `::/0` into a tunnel that carries no IPv6, so those lookups just failed | ✅ | `apps/mobile/lib/core/xray/xray_config.dart` (IPv4-only resolver lists, `_isIpv6Literal` filter on chosen servers), `services/api/src/nebula_api/provisioning/service.py` (`_AD_BLOCK_DNS_SERVER`). Server-side half deployed with #198; the client-side half ships in the next mobile release |
| H-4 | No HSTS/CSP/`X-Frame-Options` on the admin panel (`:8444`) or API edge | ✅ | Deployed on both ports 2026-09-17 and confirmed live with `curl -I` after the reboot. `:8445` from the tracked `xray-8445.conf`; `:8444` by hand in `/etc/nginx/sites-enabled/nebula` (untracked, host-specific), on both the `panel.` and `api.` blocks. Backups of that file now live in `/root/nginx-backups/`, **not** beside it -- `nginx.conf` globs `sites-enabled/*` with no extension filter, so a `.bak` left there is loaded as a second copy of every server block it contains |

## Medium

| # | Finding | Status | Where |
|---|---|---|---|
| M-1 | Argon2id (165 ms/verify) ran inline in the async event loop — a burst of logins could stall the whole API | ✅ | `services/api/src/nebula_api/passwords.py`: `hash_password_async`/`verify_password_or_dummy_async` on a bounded `ThreadPoolExecutor`. All call sites in `user_service.py`, `admin_service.py`, `accounts/service.py` switched over. Deployed 2026-09-17 |
| M-2 | No edge rate limiting (`limit_req`) at nginx; app-level limits bucket IPv6 by `/64` | ✅ | Zone declared in its own drop-in, `/etc/nginx/conf.d/nebula-ratelimit.conf` (that directory is included into `http{}` at `nginx.conf` line 59, so no distribution-managed file needed editing). Applied to `:8444`'s `api.` block. **Deliberately not applied to the `panel.` block**: it serves a Next.js app whose cold page load asks for dozens of chunks at once, and 20r/s would answer its own assets with 503s. `:8445`'s `/v1/` still carries the line commented out -- uncomment it there if that port starts taking real client load |
| M-3 | nginx logs every `/xhttp` tunnel request with client IP (33k lines/day, 14-day rotation) — the threat model forbids logs becoming a traffic-surveillance dataset | ✅ | `access_log off;` deployed on `:8445` (covers both `/xhttp` and `/v1/` on that port — this is the port real clients actually use for both). `:8444`'s own access log is a smaller-volume judgment call left to the operator, see README |
| M-4 | No retention job — `reconciliation_records`, `agent_operations`, `server_health`, `email_deliveries`, `audit_logs` grew forever on a disk shared with the database, against a documented 365/90-day policy | ✅ | `services/api/src/nebula_api/retention.py` (`prune_history`, batched deletes, FK-safe ordering, reports rather than raises when the app role can't touch `audit_logs`), `nebula-api prune-history` CLI command, compose `prune` service (migration credential), `infrastructure/systemd/nebula-prune.{service,timer}` (weekly). Integration-tested against real PostgreSQL in `test_retention_integration.py`. Timer installed and enabled on the VPS, next run Sunday 04:30 UTC |
| M-5 | Host is a hard SPOF: no swap, 38 GB disk shared with CI and other services | ✅ | 2 GB swapfile created, `swapon`'d and added to `/etc/fstab` 2026-09-17; confirmed still mounted after the reboot below. The shared-disk half stands (15 GB free after the upgrade) and is really H-2's second-VPS decision |
| M-6 | Reboot pending (kernel `6.8.0-90`), 35 pending package updates, 122-day uptime | ✅ | Upgraded and rebooted 2026-09-17, now on `6.8.0-139`, reboot flag clear. `apt-get upgrade` run with `--force-confold`/`--force-confdef` so it could not overwrite the sshd and nginx configs changed earlier the same day — both verified intact before and after |
| M-8 | **Found by the M-6 reboot, not by the original audit: `nginx.service` was `disabled`.** It had been started by hand and would not have come back from any reboot -- the API, the admin panel and the `:8445` tunnel entry point would all have stayed down until somebody noticed | ✅ | `systemctl enable --now nginx` 2026-09-17. Every other unit (`nebula-compose`, the agent, xray, hysteria, docker, fail2ban, all five timers) was checked the same way and was already enabled. Worth re-checking `is-enabled`, not just `is-active`, after any host rebuild -- the audit originally checked only the latter, which is why this went unnoticed |
| M-9 | **Missed by the original audit, found on a later pass: container logs had no size limit.** Docker's default `json-file` driver does not rotate, so every container's log grew until the disk did not have room -- on the 38 GB disk already shared with the database and the CI runner, and which has run out before. Easy to miss because the logs *looked* small (432 KB total): every container had been recreated hours earlier by the deploy and the reboot, which resets them. `usage` alone writes a line every fifteen seconds | ✅ | `x-logging` anchor in `infrastructure/compose/production.yaml`, applied to all eight services: 10 MB × 3 files, so 30 MB each. Set in the compose file rather than `/etc/docker/daemon.json` on purpose -- a daemon default needs `systemctl restart docker`, which restarts the database, and would live somewhere this repository does not track. Takes effect per service on its next recreate. **Deployed 2026-09-18**: `api`, `worker`, `admin` and `usage` recreated and confirmed carrying `max-file:3 max-size:10m`. `postgres` and `redis` were deliberately left running -- the deploy runbook keeps `--no-deps` away from them -- so they were recreated on 2026-09-21 as well, so **all six containers now carry the cap** |
| M-7 | Postgres `listen_addresses='*'` plus `local/host replication … trust` | ✅ (no action) | **Re-read on 2026-09-17 and less severe than first stated**: every `trust` line in `pg_hba.conf` is scoped to `local` (the container's own Unix socket) or `127.0.0.1/32`/`::1/128` (the container's own loopback) — these are Postgres's stock defaults and were never reachable from the Docker bridge network a tunnelled client rides, let alone the internet. The one line that *is* reachable from the bridge, `host all all all`, already requires `scram-sha-256`. Nothing to fix here beyond optionally narrowing `listen_addresses` for defense in depth — see **Host actions needed**, now optional rather than urgent |

## Low

| # | Finding | Status | Where |
|---|---|---|---|
| — | `server_tokens` on (nginx version disclosed) | ✅ | `server_tokens off;` deployed on `:8445` and on both `:8444` blocks. Confirmed: `Server: nginx`, no version |
| — | `worker` container had no healthcheck; a worker wedged on a dead mail provider looked identical to one with nothing to send | ✅ | `services/worker/src/nebula_worker/main.py` (heartbeat file after every poll, success or failure), `infrastructure/compose/production.yaml` (healthcheck reading it), `services/vpn-agent/src/nebula_agent/healthcheck.py` (`_CONTAINERS` now also watches `nebula-production-worker-1` the way it already watched `usage`). Deployed and confirmed healthy |
| — | `/v1/deployment` is public and advertises feature flags, aiding censor fingerprinting | ✅ | **Route deleted.** The earlier note here said it was needed for a client behind a blocked control-plane port; that was wrong. Nothing called it -- not the app, not the admin, not the agent, only its own tests -- so it was an unauthenticated endpoint answering `"name":"Nebula"` and a feature list to anyone who probed the tunnel port, for no one's benefit. `deployment/{routes,schemas,service}.py` and its tests are gone; the deployment identity row itself stays, because enrolment uses it. If a multi-deployment client ever needs this, re-add it then and design it not to name itself |

## Host actions needed (this assistant does not change system/security settings unilaterally)

Run on the VPS (`ssh nebula`) when ready.

**Standing constraint:** users, passwords and account state on this host are
the operator's alone. Nothing in this section, and nothing in a future
audit, should change them without being asked for by name each time.

**H-1 — SSH hardening: done 2026-09-17**, see the row above. Since 2026-10-30
`install.sh` installs and enables fail2ban (its default sshd jail) and daily
unattended security upgrades on every server it sets up, and adds a 2 GB
swapfile to a server with no swap and under 4 GB of memory (M-5). SSH password
login is left as it is: turning it off is the operator's call. To undo any
part of it:
```bash
sudo passwd -u reza                                   # unlock the account
sudo cp /etc/ssh/sshd_config.d/50-cloud-init.conf.bak \
        /etc/ssh/sshd_config.d/50-cloud-init.conf     # password login back on
sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config # root password login back on
sudo systemctl reload ssh                             # unit is `ssh`, not `sshd`
```

**H-2.** What is left is moving everything that is not Nebula off this
host. That is a second-VPS decision, worth making before going public.

**M-5 (swap) and M-6 (upgrade + reboot): done 2026-09-17**, see those rows.
Two things worth carrying into the next reboot:

- Run `apt-get upgrade` with `-o Dpkg::Options::=--force-confold -o
  Dpkg::Options::=--force-confdef`. Without them a package upgrade can
  replace `sshd_config` or an nginx vhost with the distribution's version
  and undo hardening silently.
- Afterwards, check `systemctl is-enabled`, not just `is-active`, for
  everything that matters. That is how M-8 was found: nginx was running but
  disabled, so the reboot took the whole public entry point down until it
  was started by hand.

**M-7 — Postgres (optional, not a real exposure — see the corrected row
above):** the only defense-in-depth step worth doing, if any, is narrowing
`listen_addresses` from `*` to the container's own interface. Left undone:
it saves nothing a network attacker could reach today, since C-1's ACL and
`scram-sha-256` already cover the actual reachable path.

## Next up in code

Nothing left that's fixable purely in this repo. What remains is either a
one-line host edit already spelled out in `infrastructure/nginx/README.md`
(the `:8444` headers, and the `limit_req_zone` in `nginx.conf`), or one of
the **Host actions needed** items above, which change system/security
settings and are the operator's to run.

## Deployment log

2026-09-17: #198 merged and deployed to production in the same session.
`git pull --ff-only` on `/opt/nebula`, rebuilt and recreated `api`/`worker`/
`admin`/`usage`, `migrate` confirmed a no-op (this PR added no schema
change), `nebula-prune.{service,timer}` installed and enabled,
`nebula-vpn-agent` restarted (re-rendered both the Xray and Hysteria2
served configs with the new egress ACL — confirmed live in both), and the
updated `:8445` nginx block deployed to its actual path on this host,
`/etc/nginx/sites-available/nebula-xray` (not `conf.d/` as
`infrastructure/nginx/README.md`'s install instructions describe — this
host was set up before that convention, and the README should be updated
to match, or the file migrated to match the README; neither has happened
yet). Every container reported healthy afterward, and C-1 was confirmed
closed against the live tunnel (see that row above).

Client-side changes (the mobile app's IPv6-resolver fix, half of H-3) are
not live yet — they ship in the next release, same as always.

2026-09-17, later the same day: the remaining host work, at the operator's
request and with accounts and passwords explicitly out of scope. `:8444`
hardened (H-4) and rate-limited (M-2), 2 GB of swap added (M-5), all
pending packages upgraded and the host rebooted onto `6.8.0-139` (M-6).
The reboot surfaced M-8 — nginx was never enabled at boot — which is the
one finding in this document that the audit itself missed and only a
controlled restart could have found. Everything came back: six containers
healthy, all five timers armed, both transports serving with the egress
ACL intact (15 ranges on each), and `/healthz`, `/readyz`, the panel and
`:8445` all answering.
