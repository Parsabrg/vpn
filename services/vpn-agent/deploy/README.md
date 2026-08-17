# Production deployment

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
| systemd restrictions: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, private temp, restricted address families, small read/write allowlist | All present in `nebula-vpn-agent.service`; `ReadWritePaths=/var/lib/nebula/wireguard` is the only writable path, `ReadOnlyPaths=/run/nebula-secrets` is read-only even to this service |
| Bind to loopback/private interface; never public | `NEBULA_AGENT_BIND_HOST` in `/etc/nebula/agent.env` -- **must** be set to `127.0.0.1` or a private address; the packaged default (`0.0.0.0`, meant for the isolated dev container) would bind every host interface if left unset here |
| Fixed binaries and argv arrays; never a shell | Code-level: `src/nebula_agent/drivers/_exec.py::run_fixed_argv` is the only subprocess call site, always `shell=False`, argv built entirely from validated `Settings`/request fields |
| Validate interface names, IP pools, public keys, credential formats, operation sizes | Code-level: `Settings` field validators, `drivers/base.py`'s typed Pydantic request models, `drivers/wireguard.py::validate_address_in_client_pool` |
| Pin the Xray binary and trusted templates; no paths/config fragments over the API | Code-level: `Settings.reject_unimplemented_xray_driver` hard-rejects `xray_enabled=True` outright until Xray's own delivery milestone |
| WireGuard/credential private keys root-owned, mode 0600 | Deployment step below -- not something the unit file alone can enforce |
| Apply configuration atomically, keep a last-known-good recovery path | Code-level: `drivers/config_store.py::ConfigStore` (atomic candidate write + promote-or-rollback), used identically by both drivers |

## Install

1. Create the service user and directories:
   ```shell
   useradd --system --no-create-home --shell /usr/sbin/nologin nebula-agent
   install -d -o root -g nebula-agent -m 0750 /run/nebula-secrets
   install -d -o nebula-agent -g nebula-agent -m 0700 /var/lib/nebula/wireguard
   ```
2. Place the WireGuard server private key, the agent's TLS certificate/key,
   and the trusted client CA under `/run/nebula-secrets/`, owned `root:nebula-agent`,
   mode `0640` (root-writable, group-readable only by the service):
   ```shell
   chown root:nebula-agent /run/nebula-secrets/*
   chmod 0640 /run/nebula-secrets/*
   ```
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
   NEBULA_WG_SERVER_PRIVATE_KEY_FILE=/run/nebula-secrets/wireguard_server_private_key
   NEBULA_AGENT_TLS_CERT_FILE=/run/nebula-secrets/agent_tls_cert
   NEBULA_AGENT_TLS_KEY_FILE=/run/nebula-secrets/agent_tls_key
   NEBULA_AGENT_TRUSTED_CLIENT_CA_FILE=/run/nebula-secrets/agent_trusted_client_ca
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
6. Install and start the agent unit:
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
