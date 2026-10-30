# Production deployment

> **Installing a new server? Run `sudo ./install.sh` from the repository root;**
> it does every step below. This page documents what it does, for an
> installation set up by hand.


This is the real deployment path. The Docker/Compose stack in the repo root
never runs `NativeWireGuardDriver` (see `../README.md`) -- it is dev/CI
scaffolding only. Production is a hardened systemd service running directly
on the VPN host, one per server, matching `docs/architecture.md`'s
"For one VPS, a server row identifies the local agent" model.

## Threat model checklist -> unit file mapping

`docs/threat-model.md`'s "Agent hardening" checklist, and exactly what
satisfies each line:

| Checklist item | Satisfied by |
|---|---|
| Dedicated service identity, only required capabilities | `User=`/`Group=nebula-agent`, `AmbientCapabilities=`/`CapabilityBoundingSet=CAP_NET_ADMIN` (the only capability granted) |
| systemd restrictions: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, private temp, restricted address families, small read/write allowlist | All present in `nebula-vpn-agent.service`; `ReadWritePaths=/var/lib/nebula/wireguard` is the only writable path, `ReadOnlyPaths=/etc/nebula/secrets` is read-only even to this service |
| Bind to loopback/private interface; never public | `NEBULA_AGENT_BIND_HOST` in `/etc/nebula/agent.env` -- **must** be set to `127.0.0.1` or a private address; the packaged default (`0.0.0.0`, meant for the isolated dev container) would bind every host interface if left unset here. Exception: if `api` runs colocated via `infrastructure/compose/`, its container can't reach a literal `127.0.0.1` (that's the container's own loopback, not the host's) -- bind the compose backend network's gateway (`172.30.101.1`) there instead, which is reachable from that network and from no public interface, per `infrastructure/compose/README.md`. `0.0.0.0` plus a firewall rule also works but leaves the firewall as the only thing between the control plane and the internet |
| Fixed binaries and argv arrays; never a shell | Code-level: `src/nebula_agent/drivers/_exec.py::run_fixed_argv` is the only subprocess call site, always `shell=False`, argv built entirely from validated `Settings`/request fields |
| Validate interface names, IP pools, public keys, credential formats, operation sizes | Code-level: `Settings` field validators, `drivers/base.py`'s typed Pydantic request models, `drivers/wireguard.py::validate_address_in_client_pool` |
| Pin the Xray binary and trusted templates; no paths/config fragments over the API | Code-level: `Settings.reject_unimplemented_xray_driver` hard-rejects `xray_enabled=True` outright until Xray's own delivery milestone |
| WireGuard/credential private keys root-owned, mode 0600 | Deployment step below -- not something the unit file alone can enforce |
| Apply configuration atomically, keep a last-known-good recovery path | Code-level: `drivers/config_store.py::ConfigStore` (atomic candidate write + promote-or-rollback), used identically by both drivers |

## Install

1. Create the service user and directories. `/etc/nebula/secrets`, not `/run`
   -- `/run` is tmpfs and is wiped on every reboot, which would otherwise
   strand the service without its keys until someone manually restored them:
   ```shell
   useradd --system --no-create-home --shell /usr/sbin/nologin nebula-agent
   install -d -o root -g nebula-agent -m 0750 /etc/nebula/secrets
   install -d -o nebula-agent -g nebula-agent -m 0700 /var/lib/nebula/wireguard
   ```
2. Place the WireGuard server private key under `/etc/nebula/secrets/`, owned
   `root:nebula-agent`, mode `0640` (root-writable, group-readable only by the
   service):
   ```shell
   chown root:nebula-agent /etc/nebula/secrets/*
   chmod 0640 /etc/nebula/secrets/*
   ```
   The agent's TLS certificate, its key, and the trusted client CA are *not*
   placed by hand -- step 6 obtains them from the control plane.
3. Install the package into a dedicated virtualenv:
   ```shell
   python3 -m venv /opt/nebula-vpn-agent/.venv
   /opt/nebula-vpn-agent/.venv/bin/pip install /path/to/services/vpn-agent
   ```
4. Write `/etc/nebula/agent.env` (mode `0640`, owned `root:nebula-agent`) with
   at minimum:
   ```
   NEBULA_ENV=production
   NEBULA_WG_DRIVER=native
   NEBULA_AGENT_BIND_HOST=127.0.0.1
   NEBULA_WG_SERVER_PRIVATE_KEY_FILE=/etc/nebula/secrets/wireguard_server_private_key
   NEBULA_AGENT_TLS_CERT_FILE=/etc/nebula/secrets/agent_tls_cert
   NEBULA_AGENT_TLS_KEY_FILE=/etc/nebula/secrets/agent_tls_key
   NEBULA_AGENT_TRUSTED_CLIENT_CA_FILE=/etc/nebula/secrets/agent_trusted_client_ca
   NEBULA_WG_SERVER_ADDRESS=<this host's real WireGuard address>/24
   NEBULA_WG_CLIENT_POOL=<this host's real client pool>/24
   NEBULA_WG_PUBLIC_ENDPOINT=<this host's public DNS name or IP>:51820
   ```
   (the full field list and defaults are in `../src/nebula_agent/settings.py`;
   anything not set here falls back to that default).
5. Bring the WireGuard interface up once, outside the agent's own request
   path -- e.g. via a `wg-quick`-managed `/etc/wireguard/wg0.conf` containing
   only `[Interface]` (private key, address, listen port) and no `[Peer]`
   blocks, enabled with `systemctl enable --now wg-quick@wg0`. The agent only
   ever syncs peers onto an interface that already exists; it never creates
   one.
6. Enrol this node, which is how it obtains the TLS identity it serves
   under. On the control plane, mint a token for it:
   ```shell
   docker compose exec api nebula-api create-enrollment-token --label node-02
   ```
   Move the token to this host by whatever means you already trust, put it in
   a file, and exchange it:
   ```shell
   /opt/nebula-vpn-agent/.venv/bin/nebula-agent-enroll --control-plane https://api.example.com:8444 --public-host <this host's public DNS name or IP> --token-file /root/enrollment-token
   rm /root/enrollment-token
   ```
   The private key is generated here and never leaves this host; what crosses
   the network is a certificate request and the token. The token is single
   use and short-lived, so one read from a shell history afterwards is inert.

   Pass `--agent-host` when the control plane reaches this agent at a
   different address from the one clients dial -- a private network address,
   typically. Pass `--control-plane-ca` when the control plane does not have
   a publicly trusted certificate; there is deliberately no way to skip
   verification, because the token is a bearer credential and sending it to
   an unverified endpoint sends it to whoever answered.

   Running it again on an enrolled node changes nothing and exits zero, so an
   installer that reruns is safe.
7. Install and start the agent unit:
   ```shell
   cp nebula-vpn-agent.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nebula-vpn-agent
   ```

## Certificate rotation

uvicorn terminates TLS directly (see `../src/nebula_agent/serve.py`), which
means rotating `NEBULA_AGENT_TLS_CERT_FILE`/`_KEY_FILE`/
`NEBULA_AGENT_TRUSTED_CLIENT_CA_FILE` requires `systemctl restart
nebula-vpn-agent` -- there is no hot-reload. `Restart=on-failure` does not by
itself pick up a rotated certificate; rotation must trigger an explicit
restart. `docs/threat-model.md` already accepts certificate lifecycle as a
residual risk needing an operational runbook, which this is.

## Checking what clients are actually told to dial

```shell
/opt/nebula-vpn-agent/.venv/bin/nebula-agent-check
```

Connects to every endpoint this agent advertises and reports which ones
answer. Run it after changing inbounds, TLS, nginx, or firewall rules, and
before announcing a release.

It exists because two transports shipped advertising an endpoint nothing
answered on. XHTTP sent every client to a loopback port with TLS disabled from
the day it was written, and Hysteria2 ran without the obfuscation it claimed.
Both looked healthy from the server -- process up, config valid, unit active,
provisioning returning success -- and both could only be seen by connecting
the way a client does.

The addresses come from the driver's own response mapping rather than being
recomputed from settings, so a mistake in that mapping shows up here instead
of being reproduced and agreed with.

Hysteria2 reports `SKIP`. It is QUIC over UDP, and a UDP socket accepts a
connect and sends into the void whether or not anything is listening, so
"connected" would prove nothing. Verifying it needs a real client.
