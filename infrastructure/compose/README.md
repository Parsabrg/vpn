# Production deployment

> **Installing a new server? Run `sudo ./install.sh` from the repository root;**
> it does every step below. This page documents what it does, for an
> installation set up by hand.


This is the containerized half of production: `postgres`, `redis`, `api`, `worker`,
and `admin`, run via `production.yaml` and supervised by one systemd unit
(`../systemd/nebula-compose.service`). It does **not** include the VPN agent --
that runs as its own hardened bare-metal systemd service for its `CAP_NET_ADMIN`
requirement; see `../../services/vpn-agent/deploy/README.md` for that half of the
install, including how `/etc/nebula/secrets` (reused here for the same purpose --
`/etc`, not `/run`, since `/run` is tmpfs and would lose every secret on
reboot) gets populated with the agent's own secrets. Nginx/TLS termination and off-host
backups are separate, not-yet-built pieces -- `production.yaml` publishes `api`
and `admin` to `127.0.0.1` only, ready for a future reverse proxy to front them.

`production.yaml` is standalone, not an overlay on the repo-root `compose.yaml` --
that file is dev/CI scaffolding only (hardcoded dev values, a `mailpit` sink, a
capability-free fake `vpn-agent` container) and must never run against real
secrets or a real database.

## Install

1. Check out the repository to `/opt/nebula` (or update the unit's
   `WorkingDirectory=` to match wherever it actually lives), and check out the
   exact commit you intend to deploy.

2. Create the `nebula-secrets` group at a fixed GID and populate
   `/etc/nebula/secrets/` (mode `0750`, owned `root:nebula-secrets`) with one
   file per secret, each root-writable and readable only by that group, mode
   `0640`. `api` and `worker` run as non-root, non-`root`-group UIDs (see
   their Dockerfiles) with no other way to read a root-owned file, so
   `production.yaml` adds this exact GID as a supplementary group
   (`group_add:`) on both -- the GID must match precisely, the group name
   does not (the container never sees the host's `/etc/group`):
   ```shell
   groupadd --gid 9443 nebula-secrets
   install -d -o root -g nebula-secrets -m 0750 /etc/nebula/secrets
   # after placing every file below:
   chown root:nebula-secrets /etc/nebula/secrets/*
   chmod 0640 /etc/nebula/secrets/*
   ```
   - `jwt_private_key`, `jwt_public_key` -- generate with
     `nebula-api generate-jwt-signing-key` (see `../../docs/environment.md`).
   - `token_pepper`, `mfa_encryption_key` -- generate with
     `nebula-api generate-symmetric-key --purpose token-pepper` /
     `--purpose mfa-encryption`; `xray_encryption_key` with
     `--purpose xray-encryption`. These run inside the API image, so build it
     first (`docker compose ... build api`).
   - `jwt_previous_public_keys/`, `token_previous_peppers/`,
     `mfa_previous_encryption_keys/` -- not created by default. Only needed
     once a rotation is in progress: create the directory, then add the
     matching `NEBULA_*_PREVIOUS_*_DIR` line back into `production.yaml`'s
     `api` service (commented out there by default, since `key_material.py`
     requires the directory to exist once the setting is non-empty -- a
     fresh deploy has none yet). See `../../docs/environment.md`'s "Key
     rotation procedure".
   - `agent_ca`, `agent_client_cert`, `agent_client_key` -- this stack's mTLS
     client identity for calling the VPN agent; the agent's own trusted CA and
     server certificate are separate, provisioned by
     `../../services/vpn-agent/deploy/README.md`.
   - `smtp_password` -- only if `NEBULA_EMAIL_PROVIDER=smtp` with
     authentication. `resend_api_key` -- only if `NEBULA_EMAIL_PROVIDER=resend`.
     Only the file matching the chosen provider needs real content.

3. Write `/etc/nebula/compose.env` (mode `0640`, owned `root:root`, readable
   only by systemd) with every required variable below.

4. Migrations run on `up`: the `migrate` service completes before `api`
   starts. To run them by hand first:
   ```shell
   cd /opt/nebula
   docker compose -f infrastructure/compose/production.yaml \
     --env-file /etc/nebula/compose.env run --rm migrate
   ```

5. Install and start the stack:
   ```shell
   cp infrastructure/systemd/nebula-compose.service \
      infrastructure/systemd/nebula-prune.service \
      infrastructure/systemd/nebula-prune.timer \
      /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nebula-compose
   systemctl enable --now nebula-prune.timer
   ```

   `nebula-prune.timer` runs the isolated Compose `prune` service weekly. It
   uses the migration role only for that run so the API role remains unable to
   alter or delete audit evidence.

## Required `/etc/nebula/compose.env` variables

| Variable | Purpose |
| --- | --- |
| `POSTGRES_DB` | Database name |
| `POSTGRES_SUPERUSER` | Postgres superuser used only for role bootstrap |
| `POSTGRES_SUPERUSER_PASSWORD` | Superuser password |
| `NEBULA_DB_APP_USER` / `NEBULA_DB_APP_PASSWORD` | Least-privilege application DML role |
| `NEBULA_DB_MIGRATOR_USER` / `NEBULA_DB_MIGRATOR_PASSWORD` | DDL-capable migration-only role |
| `NEBULA_REDIS_PASSWORD` | Redis auth password (production requires it) |
| `NEBULA_API_PUBLIC_URL` | The API's real public origin |
| `NEBULA_ADMIN_PUBLIC_URL` | The admin dashboard's real public origin -- also becomes `admin`'s `NEBULA_ADMIN_ORIGIN` |
| `NEBULA_ALLOWED_ORIGINS` | Exact allowed CORS origin(s), comma-separated |
| `NEBULA_JWT_KEY_ID` / `NEBULA_TOKEN_KEY_VERSION` / `NEBULA_MFA_KEY_VERSION` / `NEBULA_XRAY_KEY_VERSION` | Current key/version labels matching the files placed in step 2 |
| `NEBULA_EMAIL_PROVIDER` | `smtp` or `resend` |
| `NEBULA_EMAIL_FROM` | Sender address used on outgoing mail |

Optional, with sensible defaults if omitted: `API_PORT` (8000), `ADMIN_PORT`
(3000), `NEBULA_LOG_LEVEL` (`INFO`), `NEBULA_SMTP_HOST`/`NEBULA_SMTP_PORT`/
`NEBULA_SMTP_USERNAME`/`NEBULA_SMTP_STARTTLS` (only meaningful under the `smtp`
provider).

**Registering a VPN server's agent address is not an environment variable at
all** -- `api` supports many VPN servers, each with its own agent, so the
address is a per-row database field (`vpn_servers.agent_host`/`agent_port`)
set once via the CLI once the stack is up. For a colocated agent, use the
fixed `backend` network's own gateway IP, **not** `host.docker.internal`
(that special value resolves to the *default* Docker bridge's gateway
regardless of which network a container is actually attached to -- not
reachable from `backend`, confirmed against a real deployment):
```shell
docker compose -f production.yaml --env-file /etc/nebula/compose.env \
  run --rm api nebula-api create-vpn-server \
  --code my-server --display-name "My Server" \
  --agent-host 172.30.101.1 --agent-port 9443 \
  --public-host <your WireGuard public hostname/IP> \
  --wireguard-client-pool <CIDR> --wireguard-gateway-address <address in that CIDR>
```
A remote server's agent uses its own real address instead, unaffected by any
of this.

**The agent itself must accept connections from that subnet.** Its
`NEBULA_AGENT_BIND_HOST` can't be loopback-only for a colocated agent (a
container's `127.0.0.1` is its own loopback, not the host's). Bind it to this
network's gateway address -- the same one `--agent-host` above uses:
```
NEBULA_AGENT_BIND_HOST=172.30.101.1
```
That address exists only on the compose bridge, so the listener is reachable
from the backend network and from nowhere else. `0.0.0.0` also works and was
what this recommended before; the difference is what happens when something
else goes wrong. Bound to `0.0.0.0` the agent is listening on every public
interface and only a firewall rule keeps the internet out, so flushing the
rules -- a `ufw reset`, a rule ordering mistake, a Docker iptables reload --
publishes the control plane instantly and silently. Bound to the gateway
there is nothing to expose.

Keep the firewall rule regardless; layers are the point:
```shell
sudo ufw allow from 172.30.101.0/24 to any port 9443 proto tcp
```
The agent's own mTLS requirement (a valid client certificate for every
connection, verified before any request is processed) is the third layer,
and the only one that still holds if the other two are wrong.

Binding the gateway makes the agent depend on that bridge existing, which it
does not at the instant of a reboot. `nebula-vpn-agent.service` handles this:
it orders itself after `docker.service` and disables systemd's start-rate
limit, so a boot that races the bridge retries until it wins instead of
latching into `failed`.

## Resource limits

Every service carries a `deploy.resources.limits` (cpus/memory) starting point
sized for a modest single-VPS deployment -- `postgres` the most generous since
it's the durable store, `api`/`redis` moderate, `worker`/`admin` modest. Real VPS
sizing is still open; tune these
once actual load and hardware are known rather than treating them as final.

## Updating

```shell
cd /opt/nebula
git pull
docker compose -f infrastructure/compose/production.yaml \
  --env-file /etc/nebula/compose.env build
docker compose -f infrastructure/compose/production.yaml \
  --env-file /etc/nebula/compose.env run --rm migrate
systemctl restart nebula-compose
```
