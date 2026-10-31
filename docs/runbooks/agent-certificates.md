# Agent certificates: moving to the control-plane CA

The control plane calls each server's agent over mutual TLS. Two
certificate authorities live in the control plane's state volume
(`/var/lib/nebula` in the `api` container):

| CA | Files | Signs | Who trusts it |
| --- | --- | --- | --- |
| Node CA | `node_ca_certificate`, `node_ca_key` | every agent's server certificate | the control plane, for agents |
| Control-plane CA | `client_ca_certificate`, `client_ca_key` | only the control plane's client certificate | every agent, for callers |

An agent that trusts only the control-plane CA refuses every node
certificate, including copies of old ones: nothing else is ever signed by it,
so no revocation list is needed.

`nebula-api initialize` (run at every API start) creates the control-plane CA
when it is missing. A new installation issues its client certificate from it,
and servers enrolled from then on trust it. An installation from before keeps
its node-CA client certificate and prints
`client: from the node CA; move it to the control-plane CA` until the steps
below are done. Nothing switches on its own: switching before the agents
trust the new CA would cut every one of them off.

## Moving an existing installation

Users' tunnels keep running throughout. Only the control plane's calls to
agents (new devices, removals, usage) depend on these steps. After each step,
check that every server still answers:

```bash
docker exec nebula-production-usage-1 nebula-api collect-usage   # "... 0 unreachable"
```

Below, `api` is `docker exec nebula-production-api-1` and an agent's files
are in `/etc/nebula/secrets` (`agent_tls_cert`, `agent_tls_key`, `agent_ca`;
`agent_ca` is `NEBULA_AGENT_TRUSTED_CLIENT_CA_FILE` in `/etc/nebula/agent.env`).

### 1. Deploy, so the control-plane CA exists

Deploy the release (see `deployment.md`). The `api` log, or a run of
`api nebula-api initialize`, shows `client CA: generated now` once.

### 2. Each agent: new server certificate, and trust both CAs

On each server, the control plane's own included:

```bash
cd /etc/nebula/secrets
mkdir -p /root/agent-certs-old && cp -a agent_tls_cert agent_tls_key agent_ca /root/agent-certs-old/
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out agent_tls_key.new
openssl req -new -key agent_tls_key.new -subj /CN=agent -out /tmp/agent.csr
```

Copy `/tmp/agent.csr` to the control plane and sign it there, for the
server's code as the panel shows it (names come from its record, not from
the request):

```bash
docker cp agent.csr nebula-production-api-1:/tmp/agent.csr
api nebula-api sign-server-certificate --server <code> --csr /tmp/agent.csr > agent_tls_cert.new
api cat /var/lib/nebula/client_ca_certificate > client_ca_certificate
```

Back on the server, put the new pair in place and trust both CAs (the old
one still signs the control plane's current certificate):

```bash
cd /etc/nebula/secrets
cat /root/agent-certs-old/agent_ca client_ca_certificate > agent_ca.new
for f in agent_tls_cert agent_tls_key agent_ca; do
  chown --reference=$f $f.new; chmod --reference=$f $f.new; mv $f.new $f
done
systemctl restart nebula-vpn-agent
```

Check `collect-usage` before the next server.

### 3. The control plane: its own certificate from the control-plane CA

```bash
api nebula-api rotate-control-plane-certificate
cd /opt/nebula/infrastructure/compose
docker compose -p nebula-production --env-file /etc/nebula/compose.env -f production.yaml \
  up -d --force-recreate --no-deps api worker usage
```

The old pair stays as `agent_client_certificate.old` and
`agent_client_key.old`. To go back: move them over the new ones and recreate
the same containers.

### 4. Each agent: trust only the control-plane CA

```bash
cd /etc/nebula/secrets
cp client_ca_certificate agent_ca.new
chown --reference=agent_ca agent_ca.new; chmod --reference=agent_ca agent_ca.new; mv agent_ca.new agent_ca
systemctl restart nebula-vpn-agent
```

Check `collect-usage` after each server.

### 5. Prove it

- Add a test device in the app and remove it again.
- Panel: Reconciliation → Run reconciliation now succeeds.
- A server's certificate is refused as a caller. From one server, against
  another server's agent:

  ```bash
  curl -sv --cert /etc/nebula/secrets/agent_tls_cert --key /etc/nebula/secrets/agent_tls_key \
    -k https://<other server>:9443/ 2>&1 | grep -iE "alert|unknown ca|certificate"
  ```

  The handshake ends with an `unknown ca` alert (or the connection is reset),
  never an HTTP answer.

### 6. Clean up

Once every server works: delete `/root/agent-certs-old` on each server,
`client_ca_certificate` copies outside `/etc/nebula/secrets`, and the `.old`
pair in the control plane's state volume.
