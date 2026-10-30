# Deploying to the production VPS

Everything here was established by inspecting the running host on 2026-09-07,
after a deploy that took the API down for about a minute. The outage was
caused entirely by not knowing what is in the first section, so that section
comes first.

## Where production actually lives

| | |
| --- | --- |
| Host | `203.0.113.10` (`api.example.org`, `panel.example.org`) |
| Repo checkout | `/opt/nebula`, on `main` |
| Compose project | `nebula-production` |
| Compose file | `/opt/nebula/infrastructure/compose/production.yaml` |
| Environment file | `/etc/nebula/compose.env` |
| Working directory | `/opt/nebula/infrastructure/compose` |

Confirm any of this against the running containers rather than trusting this
file, because the containers are the only thing that cannot be out of date:

```bash
docker inspect nebula-production-api-1 \
  --format '{{range $k,$v := .Config.Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}' \
  | grep compose.project
```

### The trap

**`/opt/nebula/compose.yaml` — the file at the repo root — is not
production.** It is the development compose file. It declares `name: nebula`,
it has services production does not run, and it reads no environment file, so
its `${...:-default}` fallbacks silently supply development credentials.

Using it against this host does one of two things, both bad:

- Without `-p`, it creates a **second, separate stack** called `nebula`, with
  its own empty Postgres. A migration run there reports success having
  migrated nothing that matters. The giveaway is the log: it runs *every*
  migration from `0001`, where a real deploy runs only the new ones.
- With `-p nebula-production`, Compose tries to converge the *development*
  definition onto the live stack. It attempts to recreate the shared network,
  fails because containers are attached to it, and leaves services stopped.
  **This is what caused the outage.**

Always pass all three of `-p`, `--env-file` and `-f`. The rest of this
document abbreviates them:

```bash
cd /opt/nebula/infrastructure/compose
C="docker compose -p nebula-production --env-file /etc/nebula/compose.env -f production.yaml"
```

## Deploying the API, worker and admin

### 1. Back up first, if the release contains a migration

```bash
systemctl start nebula-backup.service
journalctl -u nebula-backup.service -n 5 --no-pager
```

Writes `nebula-backup-<timestamp>.tar.gz.age`, age-encrypted, to the
configured B2 bucket. `backup.sh` reads the same compose file and env file
this runbook names -- it is worth reading if you ever doubt those paths.

### 2. Pull

```bash
git -C /opt/nebula pull --ff-only
```

Note what this does immediately, before any container is touched: the VPN
agent's virtualenv is an **editable install** pointing at
`/opt/nebula/services/vpn-agent/src`, so pulling changes the agent's code on
disk at once. It keeps running the old code only until something restarts it.

### 3. Build

```bash
$C build api worker admin migrate
```

**`migrate` is its own image tag even though it builds from `services/api`.**
Building `api` alone does not rebuild it, so it keeps a stale set of
migrations, and `alembic upgrade head` then finds nothing to do and **exits
0**. That looks exactly like success. If a migration you expect does not
appear in the log, this is why -- name it explicitly, as above.

It used to sit behind a `tools` profile and be run by hand. It no longer
does: `docker compose up -d` has to take a fresh host all the way to a
working deployment, which it cannot do if the schema step is one an operator
has to know about. `api` now waits for it to *complete*, not merely start.

### 4. Migrate

`up -d` runs this for you. Run it explicitly when you want to read the
output before anything is recreated.

```bash
$C run --rm --no-TTY migrate
docker exec nebula-production-postgres-1 \
  psql -U postgres -d nebula -tAc "select version_num from alembic_version"
```

Read the output. A real upgrade names the revision:

```
INFO [alembic.runtime.migration] Running upgrade 20260903_0009 -> 20260906_0010, ...
```

Silence between "Will assume transactional DDL" and the exit means nothing
ran. Check the head afterwards regardless.

### 5. Recreate the containers

```bash
$C up -d --force-recreate --no-deps api worker admin usage
```

`usage` is built from the API's image. Leaving it out of this line leaves the
previous release enforcing allowances.

`--no-deps` keeps Compose away from Postgres and Redis, which do not need
restarting for an application release and are the two things worth not
disturbing.

### The unavoidable 503 window

The API asserts the schema is at exactly the revision its code expects
(`SCHEMA_HEAD` in `nebula_api/db/schema.py`), so between step 4 and step 5 the
running API sees a database ahead of itself and `/readyz` returns 503. That is
correct behaviour, not a fault. Keep the gap short and do not stop halfway.

Migrating first is still the right order: the migrations in this repo are
additive or renames, so the new schema serves the old code, and the reverse is
not guaranteed.

### 6. Verify

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.org:8444/healthz   # 200
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.org:8444/readyz    # 200
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.org:8444/v1/servers/  # 401
curl -s -o /dev/null -w '%{http_code}\n' https://panel.example.org/             # 200
```

`401` on `/v1/servers/` is the healthy answer: the request reached the
application and was refused for want of a session. A `404` on a route you just
shipped means the container is still on the old image.

`:8445` serves only `/v1/`, so `/healthz` returns 404 there. That is expected;
test `:8445` with a `/v1/` path.

## What the API container does on every start

Its entrypoint prepares the installation before starting the server, and it
runs on every start rather than only the first -- a restart, a redeploy and a
crash loop all arrive there identically and it cannot tell them apart. So each
step checks whether it is already done:

- the deployment identity is generated only if there is none. A second one
  would orphan every enrolled node while looking like a clean install, which
  is why the database holds a unique index admitting exactly one row.
- the deployment secret is generated only if absent, and never replaced. It
  signs node enrolment tokens, so replacing it invalidates outstanding
  enrolments with no error anywhere.
- an existing administrator is left alone; somebody may have changed that
  password.

It waits for the database to be reachable *and* at the expected schema
revision first, because its own bootstrap writes a row into a table the
migration creates.

```bash
docker exec nebula-production-api-1 nebula-api initialize      # safe to rerun
docker exec nebula-production-api-1 nebula-api check-database  # exit 0 when ready
```

`NEBULA_SKIP_INITIALIZATION=true` starts the server without any of it.

### The state volume

`nebula-state` holds what the installation generates for itself -- today the
deployment secret. It is deliberately separate from `/etc/nebula/secrets`,
which holds operator-provided key material and is mounted **read-only**: that
separation is what lets the container generate its own secrets without the
directory holding the JWT and encryption keys being writable by the service
that reads them.

**Losing `nebula-state` invalidates every outstanding node enrolment.** Back it
up alongside the database.

## Deploying the VPN agent

The agent is not a container. Its virtualenv at `/opt/nebula-vpn-agent/.venv`
is an editable install of `/opt/nebula/services/vpn-agent/src`, so the pull in
step 2 is the deployment and this is only the restart:

```bash
systemctl restart nebula-vpn-agent
systemctl status nebula-vpn-agent --no-pager
journalctl -u nebula-vpn-agent -n 30 --no-pager
```

The restart is also how a change to the *shape* of the served config is
deployed. Provisioning only writes `/etc/nebula/xray/config.json` when the
client set changes, so a release that renders the file differently -- a new
block, a new field per client -- used to sit dormant until some unrelated user
happened to provision. The agent now re-renders at startup when what it would
write differs from what is being served, which means a restart can reload Xray
and restart Hysteria2. Both are brief, and a restart that changes nothing
reloads nothing.

Confirm it took, rather than assuming, when the release changed the rendering:

```bash
stat -c '%y' /etc/nebula/xray/config.json   # should be the restart, not older
```

A failed re-render is logged and swallowed -- the agent keeps serving the
config it already had rather than refusing to start -- so the journal is the
only place it appears.

### Changing clients without restarting Xray or Hysteria2

By default every connect and disconnect restarts `nebula-xray`, which drops
every connection on the server, and every Hysteria2 connect and disconnect
restarts `nebula-hysteria` too. With `NEBULA_XRAY_LIVE_CLIENT_UPDATES=true`:

- **Xray:** the agent adds and removes clients through Xray's API, and restarts
  only for anything else -- or when a removed client's connection is still
  carrying traffic, which removal alone does not stop.
- **Hysteria2:** its config lists no clients. It asks the agent about each new
  connection instead (`auth.type: http`, answered on `127.25.41.4:25415`), so
  the file never changes for a client, and a removed client is closed with
  Hysteria's own `/kick`. Its traffic stats listen on `127.25.41.4:25413`.

  The catch: **new Hysteria2 connections need the agent running** to be let in.
  Connections already made carry on while it restarts, and a new one fails
  until it is back -- seconds, for a deploy.

That setting turns on Xray's `HandlerService`, which can add users and whole
inbounds, and the API has no authentication. Anything on this host that can
reach it could open a proxy to the world. The CI runner runs on this host as
`gha` (see below), so **refuse it the API before turning this on**. The API gets
a loopback address of its own, 127.25.41.4, so the runner can be refused that
address and keep 127.0.0.1, which its test databases use. Nothing has to be
configured for the address: all of 127.0.0.0/8 is local.

1. Refuse the address to the runner's whole cgroup -- every job step runs
   inside it:

   ```bash
   mkdir -p /etc/systemd/system/actions.runner.Parsabrg-vpn.nebula-vps.service.d
   printf '[Service]\nIPAddressDeny=127.25.41.4\n' \
     > /etc/systemd/system/actions.runner.Parsabrg-vpn.nebula-vps.service.d/xray-api.conf
   systemctl daemon-reload
   systemctl restart actions.runner.Parsabrg-vpn.nebula-vps.service   # not mid-job
   systemctl show actions.runner.Parsabrg-vpn.nebula-vps.service -p IPAddressDeny
   ```

2. Refuse it to everything else `gha` runs. The runner's cgroup is not all of
   it: `gha` lingers, so it has its own systemd user manager
   (`user@1002.service`), which runs its rootless Docker -- and a job step can
   start processes there with `systemd-run --user`, outside the runner's
   cgroup and its rule. Measured on this host: a step reaching the address
   directly was refused, and the same step through `systemd-run --user` got
   through. The slice holds the user manager and any session `gha` opens:

   ```bash
   systemctl set-property user-1002.slice IPAddressDeny=127.25.41.4
   ```

   `set-property` applies at once and persists, as a drop-in under
   `/etc/systemd/system.control/`.

   To check both, from inside the runner's cgroup, as `gha`, the way a job step
   runs -- with something listening on the address, since the API may not be
   yet:

   ```bash
   CG=/sys/fs/cgroup$(systemctl show actions.runner.Parsabrg-vpn.nebula-vps.service -p ControlGroup --value)
   timeout 20 python3 -m http.server --bind 127.25.41.4 38460 >/dev/null 2>&1 &
   GHA="setpriv --reuid=gha --regid=gha --init-groups env XDG_RUNTIME_DIR=/run/user/1002 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1002/bus"
   bash -c "echo \$\$ > $CG/cgroup.procs
     $GHA curl -s -m 3 -o /dev/null -w 'direct: %{http_code}\n' http://127.25.41.4:38460/
     $GHA systemd-run --user --quiet --wait --pipe curl -s -m 3 -o /dev/null -w 'user manager: %{http_code}\n' http://127.25.41.4:38460/"
   ```

   Both must print `000`. Checking with `su gha` instead proves nothing: the
   process stays in the calling session's cgroup.

3. Then, in `/etc/nebula/agent.env`:

   ```bash
   NEBULA_XRAY_API_HOST=127.25.41.4
   NEBULA_XRAY_LIVE_CLIENT_UPDATES=true
   ```

   and `systemctl restart nebula-vpn-agent`. The API moving is a change to the
   config's shape, so the agent's startup re-render restarts Xray once, and
   Hysteria2 once for its switch to HTTP auth. After that, a connect should
   leave `journalctl -u nebula-xray -u nebula-hysteria` quiet.

   Measured when it was switched on, 2026-09-16: a 20 MB download on the
   phone ran to completion while another client was added and removed, with
   Xray's PID unchanged. A client removed mid-download on the server kept
   its connection for 22 seconds, until the agent saw its counters move and
   restarted Xray, which closed it. A download through a removed client can
   appear to carry on for a few seconds more: that is data already in local
   socket buffers, not traffic still being served.

Client labels in the served config are a SHA-256 digest of each client's UUID,
not the UUID, whether or not this is on: Xray reports them to anything that can
reach its API, and for VLESS the UUID is the credential.

### Shadowsocks-2022

A raw TCP+UDP inbound with no TLS, beside the VLESS transports. Its traffic
looks random, and Iran let it through at 40-80 Mbit/s to the very address
whose TLS it stalls (home line, 2026-10-22). Off unless enabled:

```bash
# /etc/nebula/agent.env
NEBULA_XRAY_SS2022_ENABLED=true
NEBULA_XRAY_SS2022_PORT=8451
NEBULA_XRAY_SS2022_SERVER_KEY=...   # openssl rand -base64 16, never rotate casually:
                                    # every client's password contains it
```

```bash
ufw allow 8451 comment 'nebula shadowsocks-2022'   # TCP and UDP
systemctl restart nebula-vpn-agent
docker compose ... exec api nebula-api seed-ss2022-protocol
docker compose ... exec api nebula-api enable-server-capability --server-code <code> --protocol-profile-code shadowsocks-2022
docker compose ... exec api nebula-api enable-server-capability --server-code <code> --protocol-profile-code shadowsocks-2022-adblock
```

Each client's key is its UUID's 16 bytes, so nothing new is stored. Its users
are added and removed live through Xray's API like VLESS (checked against
Xray 26.3.27: `adu`, `inbounduser` and `rmu` all handle them). The tunnel
always dials `NEBULA_XRAY_PUBLIC_HOST` directly; there is no TLS to front.

### VLESS Encryption and VMess

Two more direct profiles with their own encryption and no TLS, measured the
same night from the home line: VLESS Encryption 53 Mbit/s, VMess raw and
WebSocket 39-47 Mbit/s. None of them, nor Shadowsocks-2022, got through on
MCI mobile data; there the Vercel front stays the route.

```bash
xray vlessenc    # use the ML-KEM-768 pair it prints
# /etc/nebula/agent.env
NEBULA_XRAY_VLESSENC_ENABLED=true
NEBULA_XRAY_VLESSENC_DECRYPTION=mlkem768x25519plus....
NEBULA_XRAY_VLESSENC_ENCRYPTION=mlkem768x25519plus....
NEBULA_XRAY_VMESS_ENABLED=true          # 8454 raw, 8455 WebSocket (/vw)
```

```bash
ufw allow 8453/tcp; ufw allow 8454/tcp; ufw allow 8455/tcp
systemctl restart nebula-vpn-agent
docker compose ... exec api nebula-api seed-direct-protocols
# then enable-server-capability for vless-enc, vmess-raw, vmess-ws and their -adblock siblings
```

The API never routes these through the CDN: it carries TLS only.

### What the pull does not deploy

An editable install links the *source tree*, not the package metadata. So a
pull updates every module the agent already imports, and updates nothing else:

- **new dependencies** are not installed
- **new commands** do not exist, because console scripts are written into
  `.venv/bin` at install time and nowhere else

Both fail in the same confusing way -- the code is plainly there in
`/opt/nebula/services/vpn-agent/src`, and the thing that uses it is missing.
`nebula-agent-enroll` shipped, was pulled onto this host by the deploy, and
was still `command not found` when the first node enrolment was attempted an
hour later -- for exactly this reason. The `cryptography` it imports was
missing too.

So reinstall whenever a release adds either, which the diff will show as a
change to `pyproject.toml`:

```bash
/opt/nebula-vpn-agent/.venv/bin/pip install -e /opt/nebula/services/vpn-agent
ls /opt/nebula-vpn-agent/.venv/bin/ | grep nebula   # the commands that now exist
```

Reinstalling does not restart anything, so it is safe to run against a live
agent: the running process keeps the modules it already loaded, and picks the
rest up at the next restart. Running it when nothing changed is a no-op.

The agent writes `/etc/nebula/xray` and `/etc/nebula/hysteria`, both of which
must be in its unit's `ReadWritePaths`. `ProtectSystem=strict` makes anything
absent from that list read-only, and the failure is a provisioning error with
`OSError: [Errno 30] Read-only file system` buried in the journal, not a
startup failure -- so it only shows up when a user tries to connect. That is
how Hysteria2 was broken for several days.

## Host firewall for the transports

Xray dials on tunnelled clients' behalf as the `nebula-xray` user, so the
host refuses that user any *new* connection to this host and the local
networks -- the same ranges as `services/vpn-agent/src/nebula_agent/drivers/egress.py`.
Replies on connections nginx and the agent open to Xray are not new, so they
pass. It lives in ufw's own files, above ufw's blanket loopback accept, so a
reload or a reboot keeps it:

```bash
# /etc/ufw/before.rules, directly above "-A ufw-before-output -o lo -j ACCEPT"
-A ufw-before-output -m owner --uid-owner nebula-xray -m conntrack --ctstate NEW -d 127.0.0.0/8 -j REJECT
# ... and likewise for 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16
#     172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15
# /etc/ufw/before6.rules, above "-A ufw6-before-output -o lo -j ACCEPT":
#     ::1/128 fc00::/7 fe80::/10 with ufw6-before-output
ufw reload
sudo -u nebula-xray bash -c 'echo > /dev/tcp/127.0.0.1/8000'   # must be refused
```

Hysteria2 runs as root, so this cannot cover it; its ACL and resolver do
(tested 2026-10-15). A local service the transports must reach -- such as a
resolver on loopback -- needs its own narrow `ACCEPT` above these lines.

With Nebula's own resolver deployed (infrastructure/adguard/README.md),
one exception goes above those rejects: `nebula-xray` may reach
`127.0.0.1` port 5354 (UDP and TCP), the resolver's published port, and
nothing else on this host.

## Systemd units are not deployed by the pull

`/opt/nebula/infrastructure/systemd/` holds the unit files, and nothing copies
them anywhere. A release that changes a unit -- adding an `ExecStart` line to
the reconciliation sweep, widening `ReadWritePaths` -- changes the file in the
checkout and leaves the running system untouched.

Diff before assuming they match:

```bash
for unit in /opt/nebula/infrastructure/systemd/*; do
  diff -q "$unit" "/etc/systemd/system/$(basename "$unit")" 2>/dev/null     || echo "differs or missing: $(basename "$unit")"
done
```

Install the ones that changed, then reload:

```bash
cp /opt/nebula/infrastructure/systemd/nebula-reconcile.service /etc/systemd/system/
systemctl daemon-reload
```

`systemctl daemon-reload` is required -- without it systemd keeps running the
version it parsed at boot, and the file on disk saying the right thing is no
evidence at all.

## If a deploy goes wrong

Containers stopped by a failed Compose command can be started directly,
bypassing Compose's convergence logic entirely:

```bash
docker start nebula-production-postgres-1
docker start nebula-production-redis-1 nebula-production-api-1 \
             nebula-production-worker-1 nebula-production-admin-1
```

Check network attachment afterwards. A container Compose detached mid-failure
comes back with no networks, and the API then cannot resolve `postgres`:

```bash
docker inspect nebula-production-postgres-1 \
  --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
docker network connect --alias postgres \
  nebula-production_backend nebula-production-postgres-1
```

The alias matters: services address each other by Compose service name, so a
reattached container without `--alias postgres` is reachable by IP and by
nothing the application actually asks for.

To roll a migration back, every migration in this repo implements
`downgrade()`:

```bash
$C run --rm --no-TTY migrate alembic -c /app/alembic.ini downgrade -1
```

Restore from backup only if a downgrade cannot do it -- the archive is
age-encrypted and needs the operator's private key.

## The CI runner that shares this host

There is a second thing running on this VPS, and it is not part of the
deployment: a GitHub Actions self-hosted runner. It is here because the
Actions spending limit was reached and GitHub-hosted jobs stopped being
allocated at all -- no steps, no logs, every workflow failing instantly.

If you are wondering why there is a `gha` user, this is it.

| | |
| --- | --- |
| User | `gha`, uid 1002, home `/opt/actions-runner` |
| Runner service | `actions.runner.Parsabrg-vpn.nebula-vps.service` |
| Docker | rootless, `unix:///run/user/1002/docker.sock` |
| Limits | `/etc/systemd/system/actions.runner.*.d/limits.conf` |
| Weekly prune | `gha-docker-prune.timer` |
| Which jobs go where | the `CI_RUNNER` repository variable |

### What keeps it away from production

Deliberate, and worth not undoing by accident:

- `gha` has no sudo and is **not in the `docker` group**. Membership there is
  root on this host, and would let a CI step stop production containers.
- Its Docker is a **separate rootless daemon** on its own socket. `docker ps`
  as `gha` returns nothing; it cannot see `nebula-production-*`. Confirm with:

  ```bash
  su - gha -c 'export DOCKER_HOST=unix:///run/user/1002/docker.sock; docker ps'
  ```

- A systemd drop-in caps it at `CPUQuota=120%` of the 2 cores and
  `MemoryMax=1400M` of the 3.7G, at low CPU and IO weight. **There is no swap
  on this host**, so an unbounded job would leave the kernel OOM killer to
  pick a victim, and the victim could be Postgres. The cgroup limit kills the
  job inside its own cgroup instead.
- It is refused `127.25.41.4`, where Xray's API listens -- by a second drop-in,
  `xray-api.conf`, on the runner, and by `IPAddressDeny` on `user-1002.slice`,
  which covers the user manager a job could otherwise reach it through. That
  API has no authentication and, with live client updates on, can add users and
  inbounds. See "Changing clients without restarting Xray or Hysteria2".

### Three jobs cannot run here, and will not be made to

Each `runs-on: ubuntu-latest` in `.github/workflows/` says why in a comment.
In short: the Flutter container unpacks to more than this disk has free;
`netns-integration` needs sudo and creates WireGuard interfaces on a host
already serving WireGuard; `security containers` mounts
`/var/run/docker.sock`, which here is the production daemon; and
`compose smoke` publishes `127.0.0.1:8000`, which is the port
`nebula-production-api-1` already publishes.

That last one is the useful illustration: it failed by being unable to bind,
not by taking the port. Isolation is why a mistake in a workflow is a failed
build here rather than an outage.

### Turning it off

`runs-on` reads a repository variable, so moving everything back to
GitHub-hosted needs no commit:

```bash
gh variable delete CI_RUNNER     # or: gh variable set CI_RUNNER --body ubuntu-latest
```

To remove it from the host entirely:

```bash
cd /opt/actions-runner && ./svc.sh stop && ./svc.sh uninstall
su - gha -c './config.sh remove --token <token from the repo runner settings>'
systemctl disable --now gha-docker-prune.timer
userdel -r gha
```

### Watch the disk

Disk is the scarcest resource here and it is shared with production, where
running out is an outage rather than a failed build. CI images only grow, so
`gha-docker-prune.timer` clears anything untouched for a week, scoped to the
rootless daemon. Check before assuming a build failure is the build:

```bash
df -h /
```

## Adding a server

From the panel: **Server health → Add server**. Name it, and run the command
it shows on the new machine, in a clone of this repository:

```bash
sudo ./install.sh --join https://api.example.com:8444 --token v1....
```

It installs only the VPN half (Xray, Hysteria2, WireGuard, the agent, a
certificate for the server's own name), opens the agent's port 9443 to the
control plane's address alone, enrols, and enables the protocols it serves.
Assign it to users from their pages. A token works once, for half an hour.

With a CDN route configured (`NEBULA_CDN_HOST`), set `NEBULA_CDN_SERVERS` in
`compose.env` to the code of the server the CDN name points at, before a
second server joins: otherwise the second server's tunnels are sent through
the first one's CDN name and carry nothing.

### Installs older than enrolment: one certificate authority

An install set up before enrolment existed has its control-plane-to-agent
trust on a hand-made CA (`NEBULA_AGENT_TRUSTED_CA_FILE` and the two client
files in `compose.env`), while enrolment signs joined servers with the node
CA in `nebula-state`. The control plane then refuses every joined server
(`certificate verify failed: self-signed certificate in certificate chain`
in the `usage` container's log). Move the install onto the node CA once:

1. Back up `/etc/nebula/secrets/agent_*` and `compose.env`.
2. Issue the local agent a certificate from the node CA, inside the API
   container: `create_certificate_request` and `sign_node_certificate` from
   `nebula_api.pki`, with the agent's addresses (the backend gateway
   `172.30.101.1`, the public IP and name) as hostnames. Write the
   certificate, key and node CA certificate over `agent_tls_cert`,
   `agent_tls_key` and `agent_ca` (root:nebula-secrets, 0640).
3. Delete the three `NEBULA_AGENT_*_FILE` lines from `compose.env` and
   recreate `api` and `usage`: `initialize` issues their client identity from
   the node CA ("client: issued now").
4. `systemctl restart nebula-vpn-agent`.
5. Check with a single pass, which always prints its result:
   `docker exec nebula-production-usage-1 nebula-api collect-usage` must say
   `0 unreachable`. (The running poller logs only failures and changes.)

Users' tunnels keep running throughout; only the control plane's calls to
its agents pause for the seconds between steps 3 and 4. Done on the owner's
deployment 2026-10-29, with Tehran joined: `Polled 2 server(s), 0 unreachable`.

### Certificate usage: one end of the agent link each

Since 2026-10-30 an agent's certificate is issued for server use only and the
control plane's for client use only (`sign_node_certificate(usage=...)`).
OpenSSL then refuses a server's certificate presented as a client
("unsuitable certificate purpose"), so a server that is taken over cannot call
the other servers' agents as the control plane.

Certificates issued before then carry both usages and keep working; they lose
the protection only until they are re-issued:

1. **The control plane's client certificate.** Back up, then remove it and
   its key from the state volume (`agent_client_certificate` and
   `agent_client_key` under `/var/lib/nebula`) and recreate the `api` and `usage` containers: the
   entrypoint issues a new, client-only one from the node CA.
2. **Each agent's certificate.** Re-enrol the server (Add server, then
   `install.sh --join`), or sign a new one from the node CA with
   `usage="server"` and install it as `agent_tls_cert`/`agent_tls_key` the way
   the one-CA move above did, then restart `nebula-vpn-agent`.

Check afterwards with `nebula-api collect-usage`: "Polled N server(s),
0 unreachable".

