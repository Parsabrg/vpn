# Nebula VPN agent

Host-side FastAPI service exposing a narrow, typed WireGuard provisioning
operation surface (`/v1/operations/provision-device`, `revoke-device`,
`enable-device`, `disable-device`, `health`, `reconcile`), plus liveness and
readiness probes. There is no endpoint for shell commands, executable paths,
raw WireGuard configuration, raw Xray JSON, or user authentication -- every
mutating operation is a typed, validated request the agent renders into
WireGuard config text itself.

Two `WireGuardDriver` implementations exist: `FakeWireGuardRunner`, an
in-memory driver with no subprocess calls and no `NET_ADMIN` capability, and
`NativeWireGuardDriver` (milestone 5), which drives real `wg`/`wg-quick`
subprocess calls. Select which one an agent instance runs with
`NEBULA_WG_DRIVER=fake|native`.

**The real driver never runs in this repository's Docker/Compose stack.** The
Compose `vpn-agent:` service always runs `FakeWireGuardRunner`
(`NEBULA_WG_DRIVER=fake`), keeps `cap_drop: [ALL]`, and never gains
`NET_ADMIN` or a real `wg` binary -- it is a capability-free mock agent for
local development and CI smoke testing, not a deployment target. Adding real
WireGuard capability to this container would contradict that design and
spread netns/capability complexity into the stack every contributor runs, for
a capability only actually needed by the driver's own gated integration tests
and real production. `NativeWireGuardDriver` is exercised only by those gated
tests (`tests/integration/`, real kernel WireGuard interface, network
namespace-isolated) and by the real deployment path below.

Production runs as a hardened systemd service (see `deploy/`, milestone 6),
bound to loopback/a private interface, with mutual TLS terminated directly by
uvicorn (`nebula_agent.serve`) rather than a local reverse proxy -- the agent
is never publicly reachable, so a separate TLS terminator would add attack
surface for no isolation benefit. `docs/threat-model.md` covers the accepted
tradeoff (certificate rotation needs a process restart).

## Development

```shell
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
.venv/bin/uvicorn nebula_agent.main:app --reload --port 9443
```

On Windows, replace `.venv/bin/` with `.venv\\Scripts\\`.

Running the app directly with `uvicorn --reload` serves plain HTTP with the
default `FakeWireGuardRunner` -- convenient for local iteration. To exercise
the real mTLS listener, run `python -m nebula_agent.serve` with
`NEBULA_AGENT_TLS_CERT_FILE`/`NEBULA_AGENT_TLS_KEY_FILE`/
`NEBULA_AGENT_TRUSTED_CLIENT_CA_FILE` pointing at real certificates.
