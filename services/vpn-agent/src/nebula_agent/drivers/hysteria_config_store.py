"""Renders the standalone Hysteria2 server config from the provisioned
client set.

Hysteria2 does not run on Xray-core here. Xray accepts
`streamSettings.udpmasks` and silently discards it -- a client offering a
deliberately wrong Salamander password authenticates successfully -- so an
inbound configured for obfuscation has none, and a client applying real
Salamander cannot reach it at all. See docs/adr/0003 for the measurements
and docs/adr/0004 for the resulting split.

So this transport is served by the reference `hysteria` binary in its own
unit, and this module renders its config. Client bookkeeping still lives in
DesiredXrayState alongside every other transport: one provisioning flow,
one set of generations, two processes to apply to.

Unlike Xray there is no `-test` equivalent -- the binary has no way to check
a config without running it -- so the driver applies, confirms the unit came
up, and rolls back if it did not.
"""

import hashlib
from dataclasses import dataclass
from uuid import UUID

from nebula_agent.drivers.egress import BLOCKED_DESTINATIONS

# Placeholder credential for the zero-client case; see render_ below.
NO_CLIENTS_USER = "__no_clients__"


@dataclass(frozen=True, slots=True)
class HysteriaServerProfile:
    """Static per-deployment shape, built from Settings exactly as
    XrayInboundProfile is. Only the credential map varies at runtime."""

    protocol_profile_code: str
    port: int
    tls_cert_file: str
    tls_key_file: str
    obfs_password: str
    up_mbps: int
    down_mbps: int
    masquerade_url: str


TRAFFIC_STATS_PORT = 25413

# Where the agent answers Hysteria2's per-connection authentication when
# clients are changed live (see render_hysteria_server_config). Next to the
# other two internal ports, on the same protected address as Xray's API.
HYSTERIA_AUTH_PORT = 25415
HYSTERIA_AUTH_PATH = "/hysteria/auth"


def traffic_stats_secret(profile: "HysteriaServerProfile") -> str:
    """Derived from the obfuscation password, like the no-clients user.

    Deterministic so an unchanged client set renders an identical file and
    does not restart the service; derived rather than stored so there is no
    second secret to rotate. Knowing it requires already holding the secret
    that gets you to the server at all.
    """

    return hashlib.sha256(
        f"nebula-hysteria-traffic-stats:{profile.obfs_password}".encode()
    ).hexdigest()


def _no_clients_secret(profile: "HysteriaServerProfile") -> str:
    """A password nobody holds, derived so it is stable across renders.

    Deriving it from the obfuscation password means anyone who could guess it
    already has the secret needed to reach this server, so it is not a
    credential in any useful sense.
    """

    digest = hashlib.sha256(f"nebula-no-clients:{profile.obfs_password}".encode())
    return digest.hexdigest()


def _quote(value: str) -> str:
    """YAML double-quoted scalar. Every value rendered here is a UUID, a
    filesystem path, a URL or a generated password, none of which can
    legitimately contain a control character -- so escaping the two
    characters that matter is sufficient and a YAML dependency is not
    warranted for a file this shape.
    """

    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_hysteria_server_config(
    client_uuids: tuple[UUID, ...],
    profile: HysteriaServerProfile,
    *,
    api_host: str = "127.0.0.1",
    auth_url: str | None = None,
) -> str:
    """The server config, with clients either listed or asked about.

    Without `auth_url`: one `auth.userpass` entry per provisioned client. The
    UUID is used as both username and password. It is already the per-device
    secret -- issued, envelope-encrypted and revoked by the API exactly like
    every other transport's credential -- so a second secret would be one
    more thing to store, rotate and leak without making anything harder to
    guess. The catch is that the list is in the file, so every connect and
    disconnect changes the file, and Hysteria only reads it by restarting --
    which drops every Hysteria2 session on the server.

    With `auth_url`: no list. Hysteria asks the agent about each new
    connection (see nebula_agent.hysteria_auth), so the file is the same
    whoever is provisioned and never needs a restart. The agent answers with
    the client's label, not its UUID, and Hysteria names the session by it
    in its logs, its traffic counters and `/kick`.
    """

    lines = [
        "# Rendered by nebula-agent. Do not edit by hand -- every change is a",
        "# full re-render from the provisioned client set.",
        "",
        f"listen: :{profile.port}",
        "",
        "tls:",
        f"  cert: {_quote(profile.tls_cert_file)}",
        f"  key: {_quote(profile.tls_key_file)}",
        "",
        "auth:",
    ]
    if auth_url is not None:
        lines += ["  type: http", "  http:", f"    url: {_quote(auth_url)}"]
    else:
        lines += ["  type: userpass", "  userpass:", *_userpass_entries(client_uuids, profile)]

    lines += _after_auth(profile, api_host)
    return "\n".join(lines)


def _userpass_entries(client_uuids: tuple[UUID, ...], profile: HysteriaServerProfile) -> list[str]:
    if client_uuids:
        # Deterministic ordering keeps the rendered file stable, so an
        # unchanged client set produces an identical file and a diff means
        # something actually changed.
        return [
            f"    {_quote(str(client_uuid))}: {_quote(str(client_uuid))}"
            for client_uuid in sorted(client_uuids, key=str)
        ]
    else:
        # Hysteria refuses to start on an empty userpass map -- "invalid
        # config: auth.userpass: empty auth userpass" -- and a bare
        # `userpass:` key parses as null and is refused too. So the
        # zero-client case needs an entry that exists and cannot be used.
        #
        # It has to be deterministic, or every render would differ and
        # restart the service for nothing. Deriving it from the obfuscation
        # password means guessing it requires already holding the secret that
        # gets you to the server at all, so it grants nothing.
        #
        # This was previously rendered as `{}` on the reasoning that an empty
        # map authenticates nobody. It does -- by crash-looping the service,
        # 25,000 restarts deep before anyone noticed, taking the transport
        # down for everyone the moment the last client was revoked.
        return [f"    {_quote(NO_CLIENTS_USER)}: {_quote(_no_clients_secret(profile))}"]


def _after_auth(profile: HysteriaServerProfile, api_host: str) -> list[str]:
    return [
        "",
        # Where a connected client must never be able to send traffic.
        #
        # This server dials on the client's behalf from this host, and it does
        # so as root (see infrastructure/systemd/nebula-hysteria.service),
        # so without these rules "the internet" includes this machine's own
        # loopback -- the control-plane API, the admin panel, Xray's
        # unauthenticated HandlerService -- the Docker networks PostgreSQL and
        # Redis are on, the WireGuard subnet other users are on, and the cloud
        # metadata service.
        #
        # Matched after the resolver below turns a hostname into an address,
        # so a name pointing at a local address is refused too.
        "acl:",
        "  inline:",
        *[f"    - reject({destination})" for destination in BLOCKED_DESTINATIONS],
        "    - direct(all)",
        "",
        # Hysteria2 keeps per-user Tx/Rx of its own and serves them over this
        # HTTP endpoint, keyed by the username -- the client UUID, or with
        # HTTP auth the label the agent returned -- so the totals attribute to
        # a credential without any extra mapping.
        #
        # Loopback only, and with a secret: the endpoint reports every user's
        # totals and can also kick sessions, so reaching it is enough to
        # disrupt the service, not merely to read from it. On the same
        # address as Xray's API, which the host can refuse to local users
        # with no business there.
        "trafficStats:",
        f"  listen: {api_host}:{TRAFFIC_STATS_PORT}",
        f"  secret: {_quote(traffic_stats_secret(profile))}",
        "",
        "obfs:",
        "  type: salamander",
        "  salamander:",
        f"    password: {_quote(profile.obfs_password)}",
        "",
        "quic:",
        "  initStreamReceiveWindow: 8388608",
        "  maxStreamReceiveWindow: 8388608",
        "  initConnReceiveWindow: 20971520",
        "  maxConnReceiveWindow: 20971520",
        "  maxIdleTimeout: 60s",
        "  keepAlivePeriod: 10s",
        "  disablePathMTUDiscovery: false",
        "",
        "# Advisory only: ignoreClientBandwidth below puts BBR in charge, which",
        "# measures the path instead of trusting a declared number. Hysteria2's",
        "# default Brutal sender transmits at whatever the client claims, which",
        "# on a real link that is nothing like the claim means continuous",
        "# overshoot -- observed live as unusable jitter until this was set.",
        "bandwidth:",
        f"  up: {profile.up_mbps} mbps",
        f"  down: {profile.down_mbps} mbps",
        "",
        "ignoreClientBandwidth: true",
        "",
        "resolver:",
        "  type: udp",
        "  udp:",
        "    addr: 8.8.8.8:53",
        "    timeout: 10s",
        "",
        "# Anything failing authentication is transparently proxied to a real",
        "# site, so an active prober sees a working website rather than a port",
        "# that answers nothing.",
        "masquerade:",
        "  type: proxy",
        "  proxy:",
        f"    url: {_quote(profile.masquerade_url)}",
        "    rewriteHost: true",
        "",
    ]
