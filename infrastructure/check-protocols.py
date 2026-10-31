#!/usr/bin/env python3
"""Every protocol this server offers carries traffic, as the app would use it.

Run as root on a server installed with install.sh (the control plane's own
host): sudo python3 infrastructure/check-protocols.py

For each protocol the control plane has enabled here it asks the agent for a
credential, the way the control plane does when a device connects, builds the
client the app builds from the answer, fetches a page through it and removes
the credential again. WireGuard runs in a network namespace with its own
interface; the others through a local Xray client. Exits non-zero if any
protocol carries nothing, or the control plane could not hand out WireGuard
addresses here.

Stdlib only; needs docker, xray, wg, ip and curl, all present after install.sh.
"""

import ipaddress
import json
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

PAGE = "https://www.cloudflare.com/cdn-cgi/trace"
POSTGRES = "nebula-production-postgres-1"
API = "nebula-production-api-1"


def run(*args: str, **kwargs: object) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout  # type: ignore[call-overload]


def sql(query: str) -> list[str]:
    out = run("docker", "exec", POSTGRES, "psql", "-U", "postgres", "-d", "nebula", "-tAc", query)
    return [line for line in out.splitlines() if line]


def agent_env() -> dict[str, str]:
    values = {}
    for line in Path("/etc/nebula/agent.env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key] = value
    return values


class Agent:
    """The agent's operations API, called with the control plane's identity."""

    def __init__(self, workdir: Path, host: str, port: str) -> None:
        for name in ("agent_client_certificate", "agent_client_key", "node_ca_certificate"):
            (workdir / name).write_text(run("docker", "exec", API, "cat", f"/var/lib/nebula/{name}"))
        self.context = ssl.create_default_context(cafile=str(workdir / "node_ca_certificate"))
        self.context.load_cert_chain(
            workdir / "agent_client_certificate", workdir / "agent_client_key"
        )
        self.base = f"https://{host}:{port}"

    def post(self, path: str, body: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
            return json.loads(response.read())


def ids() -> dict[str, str]:
    return {"idempotency_key": str(uuid.uuid4()), "correlation_id": str(uuid.uuid4())}


def fetch(*curl_prefix: str, proxy: str | None = None) -> str:
    """The trace page's ip= line, or the last failure. A new tunnel takes a
    moment (a handshake, a client reaching its inbound), so three tries."""

    args = [*curl_prefix, "curl", "-sS", "-m", "20"]
    if proxy:
        args += ["--socks5-hostname", proxy]
    failure = ""
    for _ in range(3):
        result = subprocess.run([*args, PAGE], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("ip="):
                return line
        failure = f"failed ({result.stderr.strip() or result.returncode})"
        time.sleep(3)
    return failure


def xray_outbound(answer: dict[str, object], client_uuid: str) -> dict[str, object]:
    """The outbound the app builds for an Xray protocol (apps/mobile/lib/core/xray/xray_config.dart)."""

    address, port, sni = answer["server_address"], answer["port"], answer["sni"]
    stream: dict[str, object] = {
        "network": answer["transport"],
        "security": answer["transport_security"],
    }
    if answer["transport"] in ("xhttp", "websocket"):
        key = "xhttpSettings" if answer["transport"] == "xhttp" else "wsSettings"
        stream[key] = {"path": answer["path"]}
    elif answer["transport"] == "grpc":
        stream["grpcSettings"] = {"serviceName": answer["service_name"]}
    if answer["transport_security"] == "tls":
        stream["tlsSettings"] = {"serverName": sni}
    protocol = answer.get("protocol", "vless")
    if protocol == "shadowsocks":
        settings: dict[str, object] = {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "method": answer["method"],
                    "password": answer["password"],
                }
            ]
        }
    elif protocol == "vmess":
        users = [{"id": client_uuid, "security": "auto"}]
        settings = {"vnext": [{"address": address, "port": port, "users": users}]}
    else:
        users = [{"id": client_uuid, "encryption": answer.get("encryption") or "none"}]
        settings = {"vnext": [{"address": address, "port": port, "users": users}]}
    return {"protocol": protocol, "settings": settings, "streamSettings": stream}


def check_xray(agent: Agent, code: str, workdir: Path, socks_port: int) -> str:
    target, client_uuid = str(uuid.uuid4()), str(uuid.uuid4())
    common = {"target_kind": "xray_client", "target_id": target, "protocol_profile_code": code}
    answer = agent.post(
        "/v1/xray-operations/provision-client",
        {**ids(), **common, "desired_generation": 1, "client_uuid": client_uuid},
    )
    try:
        if answer.get("state") != "active":
            return f"not provisioned ({answer.get('state')})"
        if answer["transport"] == "hysteria":
            # The app runs the reference Hysteria2 client for this one
            # (_hysteriaYaml); the server is the same binary.
            lines = [
                f"server: {answer['server_address']}:{answer['port']}",
                f"auth: {client_uuid}:{client_uuid}",
                "tls:",
                f"  sni: {answer['sni']}",
                "  insecure: false",
            ]
            if answer.get("obfs_password"):
                lines += [
                    "obfs:",
                    "  type: salamander",
                    "  salamander:",
                    f"    password: {answer['obfs_password']}",
                ]
            lines += ["socks5:", f"  listen: 127.0.0.1:{socks_port}"]
            path = workdir / f"{code}.yaml"
            path.write_text("\n".join(lines) + "\n")
            command = ["hysteria", "client", "-c", str(path)]
        else:
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}],
                "outbounds": [xray_outbound(answer, client_uuid)],
            }
            path = workdir / f"{code}.json"
            path.write_text(json.dumps(config))
            command = ["xray", "run", "-config", str(path)]
        log = workdir / f"{code}.log"
        with log.open("w") as sink:
            client = subprocess.Popen(command, stdout=sink, stderr=subprocess.STDOUT)
            try:
                time.sleep(2)
                outcome = fetch(proxy=f"127.0.0.1:{socks_port}")
            finally:
                client.terminate()
                client.wait(timeout=10)
        if not outcome.startswith("ip="):
            # Enough to tell a name, address or certificate problem apart.
            shown = {k: answer.get(k) for k in ("server_address", "port", "sni", "transport")}
            errors = [
                line.strip()
                for line in log.read_text().splitlines()
                if any(word in line.lower() for word in ("error", "fail", "x509", "certificate"))
            ]
            outcome += f"\n       answer {shown}\n       " + "\n       ".join(errors[-3:])
        return outcome
    finally:
        agent.post(
            "/v1/xray-operations/revoke-client",
            {**ids(), **common, "desired_generation": 2, "client_uuid": client_uuid},
        )


def check_wireguard(agent: Agent, pool: str) -> str:
    private = run("wg", "genkey").strip()
    public = run("wg", "pubkey", input=private).strip()
    address = str(list(ipaddress.ip_network(pool).hosts())[-1])
    target = str(uuid.uuid4())
    answer = agent.post(
        "/v1/operations/provision-device",
        {
            **ids(),
            "target_kind": "wireguard_peer",
            "target_id": target,
            "desired_generation": 1,
            "public_key": public,
            "assigned_address": address,
            "persistent_keepalive_seconds": 25,
        },
    )
    ns = "nebula-check"
    try:
        if answer.get("state") != "active":
            return f"not provisioned ({answer.get('state')})"
        endpoint = str(answer["public_endpoint"])
        endpoint_ip = endpoint.rsplit(":", 1)[0].strip("[]")
        # A namespace reaching the server over a veth pair, as a device would
        # over the internet, with only the tunnel as its default route.
        steps = [
            ["ip", "netns", "add", ns],
            ["ip", "link", "add", "nc-host", "type", "veth", "peer", "name", "nc-ns"],
            ["ip", "link", "set", "nc-ns", "netns", ns],
            ["ip", "addr", "add", "169.254.240.1/30", "dev", "nc-host"],
            ["ip", "link", "set", "nc-host", "up"],
            ["ip", "-n", ns, "addr", "add", "169.254.240.2/30", "dev", "nc-ns"],
            ["ip", "-n", ns, "link", "set", "nc-ns", "up"],
            ["ip", "-n", ns, "link", "set", "lo", "up"],
            ["ip", "-n", ns, "route", "add", f"{endpoint_ip}/32", "via", "169.254.240.1"],
            ["ip", "-n", ns, "link", "add", "wg-check", "type", "wireguard"],
            ["ip", "-n", ns, "addr", "add", f"{address}/32", "dev", "wg-check"],
        ]
        for step in steps:
            run(*step)
        key = Path(tempfile.mkstemp()[1])
        key.write_text(private)
        run(
            "ip", "netns", "exec", ns, "wg", "set", "wg-check", "private-key", str(key),
            "peer", str(answer["server_public_key"]), "endpoint", endpoint,
            "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25",
        )
        key.unlink()
        run("ip", "-n", ns, "link", "set", "wg-check", "up")
        run("ip", "-n", ns, "route", "add", "default", "dev", "wg-check")
        resolv = Path(f"/etc/netns/{ns}")
        resolv.mkdir(parents=True, exist_ok=True)
        (resolv / "resolv.conf").write_text("nameserver 1.1.1.1\n")
        return fetch("ip", "netns", "exec", ns)
    finally:
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
        subprocess.run(["ip", "link", "del", "nc-host"], capture_output=True)
        subprocess.run(["rm", "-rf", f"/etc/netns/{ns}"], capture_output=True)
        agent.post(
            "/v1/operations/revoke-device",
            {
                **ids(),
                "target_kind": "wireguard_peer",
                "target_id": target,
                "public_key": public,
                "desired_generation": 2,
            },
        )


def main() -> int:
    env = agent_env()
    # This host's own server: the one whose agent listens where agent.env says.
    agent_host = env.get("NEBULA_AGENT_BIND_HOST", "172.30.101.1")
    servers = sql(
        "select id || '|' || code || '|' || coalesce(host(wireguard_client_pool), '') "
        f"from vpn_servers where agent_host = '{ipaddress.ip_address(agent_host)}'"
    )
    if len(servers) != 1:
        print(f"no single server record for this host's agent ({agent_host})")
        return 1
    server_id, code, pool_host = servers[0].split("|")
    codes = sql(
        "select pp.code from server_protocol_capabilities c "
        "join protocol_profiles pp on pp.id = c.protocol_profile_id "
        f"where c.state = 'enabled' and c.vpn_server_id = '{uuid.UUID(server_id)}' order by 1"
    )
    print(f"{code}: offers {', '.join(codes) or 'nothing'}")
    failures = 0
    if not codes:
        print("FAIL nothing is offered")
        failures += 1
    with tempfile.TemporaryDirectory() as directory:
        workdir = Path(directory)
        agent = Agent(workdir, agent_host, env.get("NEBULA_AGENT_BIND_PORT", "9443"))
        # Ad-block twins are the same inbound with another resolver.
        for index, profile in enumerate(c for c in codes if not c.endswith("-adblock")):
            if profile.startswith("wireguard"):
                if not pool_host:
                    outcome = "no WireGuard range on the server record: no device gets an address"
                else:
                    outcome = check_wireguard(agent, env["NEBULA_WG_CLIENT_POOL"])
            else:
                outcome = check_xray(agent, profile, workdir, 21900 + index)
            ok = outcome.startswith("ip=")
            failures += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {profile}: {outcome}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
