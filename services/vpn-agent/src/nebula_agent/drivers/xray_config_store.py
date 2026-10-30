"""Atomic on-disk Xray client-set state, mirroring drivers/config_store.py's
pattern for WireGuard.

Xray's JSON config has no `wg syncconf`-style incremental apply -- every
change is: render the full client set, write atomically, restart the Xray
process (see drivers/xray.py's module docstring for why "restart", not
"reload"). Two files are kept deliberately separate, rather than one file
serving both roles the way WireGuard's `.conf` does via a `# Generation`
comment (Xray's JSON schema has no equivalent, and relying on Xray silently
ignoring an unrecognized field inside a client object was judged too fragile
to bet a security-relevant config file on): a `xray_clients_state.json`
bookkeeping file this driver alone reads/writes to track per-client apply
generations, and the real Xray-consumed config file (owned by the driver,
not this store), always fully re-derived from whichever state this store
considers last-known-good.

One Xray process serves every configured transport at once, each as its own
`inbounds[]` entry -- mirrors how the WireGuard driver's interface shape
(listen port, address pool) comes from Settings, independent of how many
peers currently exist: an inbound's existence/port/transport is static
per-deployment config (XrayInboundProfile, built from Settings), while only
its client list varies with what's actually been provisioned.
"""

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal
from uuid import UUID

from nebula_agent.drivers.egress import BLOCKED_DESTINATIONS, RESOLVERS

Transport = Literal["xhttp", "grpc", "websocket", "raw", "hysteria"]


@dataclass(frozen=True, slots=True)
class XrayInboundProfile:
    """Static, per-deployment shape of one Xray inbound -- everything here
    comes from Settings, never from a request body or the database (the
    agent has no DB access at all, matching the rest of this package's
    design). `security="none"` means this inbound is loopback-only and
    fronted by nginx, which terminates TLS itself (today's XHTTP profile,
    the only one deployed so far); `security="tls"` means Xray terminates
    TLS directly on a public bind, matching the pattern already proven
    against the real deployment's own separate, long-running Xray setup for
    gRPC/WebSocket/raw TCP."""

    protocol_profile_code: str
    transport: Transport
    listen: str
    port: int
    security: Literal["none", "tls"]
    # Exactly one of these is set, matching `transport` -- enforced by
    # construction in settings.py's profile-building helper, not here.
    xhttp_path: str | None = None
    grpc_service_name: str | None = None
    ws_path: str | None = None
    # Hysteria2 only -- QUIC-level bandwidth hints Xray reports to the
    # client during its handshake (Mbps). Unused by every other transport.
    hysteria_up_mbps: int | None = None
    hysteria_down_mbps: int | None = None
    # Hysteria2 only -- Salamander obfuscation password (Xray-core's
    # `streamSettings.udpmasks` "finalmask" wrapper, NOT a field inside
    # hysteriaSettings itself). Without this, plain QUIC/Hysteria2 handshakes
    # are fingerprintable by DPI and get silently dropped by some ISPs
    # (confirmed live against the deployment's own ISP: packets reached the
    # host's firewall/nftables fine but the QUIC handshake never completed
    # until obfuscation was added) -- a working, shared-password reference
    # deployment on the same host uses the standalone `hysteria` binary's own
    # Salamander implementation, which is wire-INcompatible with Xray-core's
    # (see github.com/XTLS/Xray-core issue #5712, closed not-planned), but
    # that's irrelevant here since both ends of this connection (this server
    # and the mobile client) are Xray-core.
    hysteria_obfs_password: str | None = None
    # Shadowsocks-2022 only: the inbound's own key. Set, the inbound is
    # Shadowsocks rather than VLESS, on a raw TCP+UDP listener with no TLS:
    # its traffic looks random, which Iran let through at 40-80 Mbit/s to the
    # very address whose TLS it stalls (home line, 2026-10-22).
    ss2022_server_key: str | None = None
    # VLESS Encryption (Xray's own, no TLS): the server's `decryption` and
    # the `encryption` string its clients dial with, a pair from
    # `xray vlessenc`. Ran 53 Mbit/s from the home line, 2026-10-22.
    vless_decryption: str | None = None
    vless_encryption: str | None = None
    # VMess with no TLS: its own encryption, 39-47 Mbit/s from the home line.
    vmess: bool = False

    @property
    def direct(self) -> bool:
        """Dialled straight at this port with its own encryption, never
        through nginx's TLS -- unlike the loopback XHTTP inbound, the other
        security="none" profile."""

        return self.ss2022_server_key is not None or self.vless_decryption is not None or self.vmess


SS2022_METHOD = "2022-blake3-aes-128-gcm"


def ss2022_user_key(client_uuid: UUID) -> str:
    """A client's Shadowsocks-2022 key: its UUID's 16 bytes, which is the
    key length this method takes. The UUID already is the client's
    credential, so this hands out nothing it did not have."""

    return base64.b64encode(client_uuid.bytes).decode()


def uuid_from_ss2022_key(key: str) -> UUID:
    return UUID(bytes=base64.b64decode(key))


@dataclass(frozen=True, slots=True)
class RenderedXrayClient:
    client_uuid: UUID
    protocol_profile_code: str
    # The desired_generation of the request that last successfully applied
    # this client -- mirrors RenderedPeer.generation's role for WireGuard.
    generation: int = 0


@dataclass(frozen=True, slots=True)
class DesiredXrayState:
    """The full client set the next candidate should contain -- always
    complete, matching how the WireGuard driver treats DesiredInterfaceState:
    Xray's config is fully re-rendered on every change, never patched."""

    clients: tuple[RenderedXrayClient, ...] = ()

    def with_client(self, client: RenderedXrayClient) -> "DesiredXrayState":
        """Add the client, or replace the existing entry with the same UUID."""
        remaining = tuple(c for c in self.clients if c.client_uuid != client.client_uuid)
        return DesiredXrayState(clients=(*remaining, client))

    def without_client(self, client_uuid: UUID) -> "DesiredXrayState":
        return DesiredXrayState(
            clients=tuple(c for c in self.clients if c.client_uuid != client_uuid)
        )

    def client(self, client_uuid: UUID) -> RenderedXrayClient | None:
        return next((c for c in self.clients if c.client_uuid == client_uuid), None)

    def clients_for(self, protocol_profile_code: str) -> tuple[RenderedXrayClient, ...]:
        return tuple(c for c in self.clients if c.protocol_profile_code == protocol_profile_code)


def render_state_json(desired: DesiredXrayState) -> str:
    payload = [
        {
            "uuid": str(c.client_uuid),
            "profile": c.protocol_profile_code,
            "generation": c.generation,
        }
        for c in desired.clients
    ]
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_state_json(text: str) -> DesiredXrayState:
    """Parse text this module rendered -- not a general-purpose parser."""

    payload = json.loads(text) if text.strip() else []
    return DesiredXrayState(
        clients=tuple(
            RenderedXrayClient(
                client_uuid=UUID(entry["uuid"]),
                protocol_profile_code=entry["profile"],
                generation=entry["generation"],
            )
            for entry in payload
        )
    )


def client_email(client_uuid: UUID) -> str:
    """The label Xray keys a client's traffic counters on.

    A SHA-256 digest of the client UUID, never the UUID itself. Xray hands
    this label to anything that can reach its API -- counter names, user
    listings, `rmu` arguments -- and for VLESS the UUID is the credential.
    Using it as the label put every user's credential one loopback call away
    from any local process.

    It is the same digest `usage.digest_identity` reports, so the control
    plane attributes counters exactly as it did when the label was the UUID.
    A test holds the two together.
    """

    return hashlib.sha256(str(client_uuid).encode()).hexdigest()


def _stream_settings(profile: XrayInboundProfile) -> dict[str, object]:
    network: dict[str, object] = {"network": profile.transport}
    if profile.transport == "xhttp":
        network["xhttpSettings"] = {"path": profile.xhttp_path}
    elif profile.transport == "grpc":
        network["grpcSettings"] = {"serviceName": profile.grpc_service_name}
    elif profile.transport == "websocket":
        network["wsSettings"] = {"path": profile.ws_path}
    elif profile.transport == "hysteria":
        network["hysteriaSettings"] = {
            "version": 2,
            "up": str(profile.hysteria_up_mbps),
            "down": str(profile.hysteria_down_mbps),
        }
        if profile.hysteria_obfs_password:
            # Top-level streamSettings field, not inside hysteriaSettings --
            # Xray-core's finalmask subsystem wraps the underlying packet
            # conn generically, shared across transports that support it.
            network["udpmasks"] = [
                {
                    "type": "salamander",
                    "settings": {"password": profile.hysteria_obfs_password},
                }
            ]
    # "raw" needs no per-transport settings block at all.
    network["security"] = profile.security
    return network


_INTERNET_TAG = "internet"
_BLOCKED_TAG = "blocked"
_DNS_TAG = "nebula-dns"


def render_xray_server_config(
    desired: DesiredXrayState,
    profiles: tuple[XrayInboundProfile, ...],
    *,
    tls_cert_file: str | None,
    tls_key_file: str | None,
    api_host: str = "127.0.0.1",
    live_client_updates: bool = False,
    dns_redirect: tuple[str, str] | None = None,
) -> str:
    """One `inbounds[]` entry per configured profile, each with its own
    port/transport/client list. A `security="tls"` inbound gets Xray's own
    `tlsSettings.certificates` pointing at the shared cert/key files
    (`tls_cert_file`/`tls_key_file` -- required whenever any profile needs
    them, enforced by the driver, not this pure render function).

    Hysteria2 is not VLESS -- it is Xray-core's own `protocol: "hysteria"`,
    identifying clients by a bearer `auth` string (this driver reuses the
    client's UUID verbatim as that string) rather than VLESS's `id`, and
    its TLS must advertise `h3` (QUIC/HTTP-3's ALPN token, required for the
    handshake to complete at all -- Hysteria2 runs over QUIC, not TCP)."""

    inbounds = []
    for profile in profiles:
        clients = desired.clients_for(profile.protocol_profile_code)
        stream_settings = _stream_settings(profile)
        if profile.security == "tls":
            tls_settings: dict[str, object] = {
                "certificates": [{"certificateFile": tls_cert_file, "keyFile": tls_key_file}]
            }
            if profile.transport == "hysteria":
                tls_settings["alpn"] = ["h3"]
                tls_settings["minVersion"] = "1.3"
                tls_settings["maxVersion"] = "1.3"
            stream_settings["tlsSettings"] = tls_settings
        if profile.transport == "hysteria":
            protocol = "hysteria"
            settings: dict[str, object] = {
                "version": 2,
                "clients": [{"auth": str(c.client_uuid)} for c in clients],
            }
        elif profile.vmess:
            protocol = "vmess"
            settings = {
                "clients": [
                    {"id": str(c.client_uuid), "email": client_email(c.client_uuid)}
                    for c in clients
                ],
            }
        elif profile.ss2022_server_key is not None:
            protocol = "shadowsocks"
            settings = {
                "method": SS2022_METHOD,
                "password": profile.ss2022_server_key,
                "network": "tcp,udp",
                "clients": [
                    {
                        "password": ss2022_user_key(c.client_uuid),
                        "email": client_email(c.client_uuid),
                    }
                    for c in clients
                ],
            }
        else:
            protocol = "vless"
            # `email` is what Xray keys its per-user traffic counters on, and
            # it is the only identifier the stats API reports. Without it
            # every byte lands in the inbound total with nothing to say whose
            # it was, so usage could be measured for the server and never for
            # a person. It is a digest of the UUID rather than the UUID -- see
            # client_email -- and also what a live `rmu` names a client by.
            settings = {
                "clients": [
                    {"id": str(c.client_uuid), "email": client_email(c.client_uuid)}
                    for c in clients
                ],
                "decryption": profile.vless_decryption or "none",
            }
        inbounds.append(
            {
                "tag": profile.protocol_profile_code,
                "listen": profile.listen,
                "port": profile.port,
                "protocol": protocol,
                "settings": settings,
                "streamSettings": stream_settings,
            }
        )

    # StatsService for the usage collector. HandlerService only when clients
    # are changed live: it can add users and whole inbounds, so it is not
    # switched on for a deployment that has no use for it.
    services = ["StatsService"]
    if live_client_updates:
        services = ["HandlerService", "StatsService"]
    config = {
        "inbounds": [*inbounds, _stats_api_inbound(api_host)],
        "outbounds": [
            # Names resolved by Xray's own resolvers below, never the host's:
            # the host resolves `localhost` (and /etc/hosts names) to
            # loopback, which public resolvers do not -- so with the default
            # the routing check saw no address, let the name through, and
            # this outbound then dialled 127.0.0.1 (measured on 26.3.27,
            # 2026-10-15). IPv4 only, not `UseIP`: that picks IPv4 or IPv6
            # per connection, and YouTube ties a video's stream to the
            # address that asked for the page -- with this host on both,
            # videos opened and never played (seen on the phone 2026-10-17).
            {
                "tag": _INTERNET_TAG,
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIPv4"},
            },
            {"tag": _BLOCKED_TAG, "protocol": "blackhole"},
            # Every connection it takes goes to the resolver and nowhere
            # else, whatever the client named: it cannot reach anything the
            # block below protects.
            *(
                [
                    {
                        "tag": _DNS_TAG,
                        "protocol": "freedom",
                        "settings": {"redirect": dns_redirect[1]},
                    }
                ]
                if dns_redirect
                else []
            ),
        ],
        # Resolved here rather than by the host's resolver, for two reasons.
        # The routing rules below can only compare a destination address
        # against the private ranges if something has turned a hostname into
        # an address first, and `domainStrategy` below is what asks for that.
        # And a deployment that keeps this process off loopback entirely --
        # the firewall rule that backs up these rules, see
        # docs/runbooks/production-readiness-audit.md -- cannot also rely on
        # systemd-resolved at 127.0.0.53, which is what /etc/resolv.conf
        # points at on this distribution.
        "dns": {"servers": list(RESOLVERS)},
        # Counters are off by default and cost nothing to keep: Xray only
        # accumulates what `policy` asks for, and reading them is a local gRPC
        # call on a loopback-only port.
        "stats": {},
        "api": {"tag": _STATS_API_TAG, "services": services},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "routing": {
            # A rule carrying only addresses cannot match a request that names
            # a host, because at that point nothing has resolved it -- so
            # `internal.example.com` pointing at 127.0.0.1 would sail past the
            # block below and `freedom` would dial loopback. This setting is
            # what makes Xray resolve such a request and try the rules again
            # against the address it got back.
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                # Must be first, or a later rule could swallow the API traffic
                # and the stats port would answer nothing.
                {"type": "field", "inboundTag": [_STATS_API_TAG], "outboundTag": _STATS_API_TAG},
                # Before the block: the clients' DNS address is a reserved
                # one, and only its port 53 goes to this host's resolver.
                *(
                    [
                        {
                            "type": "field",
                            "ip": [dns_redirect[0]],
                            "port": "53",
                            "outboundTag": _DNS_TAG,
                        }
                    ]
                    if dns_redirect
                    else []
                ),
                # Everything a tunnelled client sends is dialled by the
                # `freedom` outbound above, from this host, as this service's
                # user -- so without this rule "the internet" includes this
                # server's own loopback, the Docker networks the control plane
                # and its database sit on, and the cloud metadata service. The
                # local addresses reachable that way included Xray's own
                # HandlerService, which can add users and inbounds and has no
                # authentication of its own.
                {"type": "field", "ip": list(BLOCKED_DESTINATIONS), "outboundTag": _BLOCKED_TAG},
                # And by name, for the one public resolvers leave unresolved.
                {
                    "type": "field",
                    "domain": ["full:localhost", "domain:localhost"],
                    "outboundTag": _BLOCKED_TAG,
                },
            ],
        },
    }
    return json.dumps(config, indent=2)


# Loopback only. The stats service has no authentication of its own, so the
# bind address is the whole access control -- anything that can reach this
# port can read every user's traffic totals.
#
# Deliberately NOT 10085, which is Xray's documented default for this and
# therefore the one port another Xray on the same host is most likely to
# already hold. That is not hypothetical: this host also ran another
# Xray whose stats API had 10085, so the agent's collector read
# *that* process's counters and wrote another service's traffic into this
# system's usage table -- and the next config render would have failed to
# bind. Paired with the Hysteria stats port instead: both are internal
# loopback endpoints, in a range no conventional service claims.
_STATS_API_TAG = "nebula-stats-api"
STATS_API_HOST = "127.0.0.1"
STATS_API_PORT = 25414


def _stats_api_inbound(api_host: str) -> dict[str, object]:
    return {
        "tag": _STATS_API_TAG,
        "listen": api_host,
        "port": STATS_API_PORT,
        "protocol": "dokodemo-door",
        "settings": {"address": api_host},
    }


def _write_atomically(
    text: str, *, directory: Path, target: Path, prefix: str, mode: int | None = None
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    descriptor, tmp_name = tempfile.mkstemp(dir=directory, prefix=prefix)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            # mkstemp always creates its temp file 0600 (owner-only), which
            # is right for this driver's own bookkeeping files but wrong for
            # the real Xray config: that file is read by the separate
            # nebula-xray systemd unit, running as a different, unprivileged
            # user (see infrastructure/systemd/nebula-xray.service) -- 0600
            # would leave it permanently unreadable to that process no
            # matter how directories/groups are set up around it.
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target


class XrayConfigStore:
    """Owns every on-disk file involved in the Xray apply pipeline: this
    driver's own bookkeeping state (see module docstring) AND the real
    config file the Xray process itself reads -- both injected as explicit
    directories, mirroring drivers/config_store.py's ConfigStore taking an
    explicit state_dir rather than deriving one from Settings internally, so
    the driver never needs to touch a real host path in a test.

    Layout under state_dir:
      xray_clients_state.json           -- last-known-good bookkeeping state
      candidate/xray_clients_state.json -- a just-rendered, not-yet-promoted candidate
      candidate/xray_config_validate.json -- a scratch copy validated with `xray run -test`
                                            before ever being promoted
    Layout under xray_config_dir:
      config.json -- the file the real Xray process reads; always fully
                      re-derived from whichever state this store considers
                      last-known-good
    """

    def __init__(self, state_dir: PurePosixPath, xray_config_dir: PurePosixPath) -> None:
        self._state_dir = Path(str(state_dir))
        self._xray_config_dir = Path(str(xray_config_dir))

    @property
    def last_known_good_path(self) -> Path:
        return self._state_dir / "xray_clients_state.json"

    @property
    def candidate_path(self) -> Path:
        return self._state_dir / "candidate" / "xray_clients_state.json"

    @property
    def validate_scratch_path(self) -> Path:
        # Must end in .json -- Xray infers its config format from the file
        # extension (not content-sniffed), and rejects an unrecognized
        # extension outright ("Failed to get format of ...") regardless of
        # what the file actually contains. Confirmed live against the real
        # `xray` binary, where a `config.json.validate` name always failed
        # `xray run -test` even with byte-identical, otherwise-valid JSON.
        return self._state_dir / "candidate" / "xray_config_validate.json"

    @property
    def xray_config_path(self) -> Path:
        return self._xray_config_dir / "config.json"

    def read_last_known_good(self) -> DesiredXrayState:
        if not self.last_known_good_path.exists():
            return DesiredXrayState()
        return parse_state_json(self.last_known_good_path.read_text())

    def render_candidate(self, desired: DesiredXrayState) -> str:
        return render_state_json(desired)

    def write_candidate_atomically(self, text: str) -> Path:
        return _write_atomically(
            text,
            directory=self.candidate_path.parent,
            target=self.candidate_path,
            prefix=".xray_clients_state.",
        )

    def promote_candidate_to_last_known_good(self, candidate: Path) -> None:
        """Called only after the caller has confirmed the candidate was applied successfully."""

        os.replace(candidate, self.last_known_good_path)

    def write_validate_scratch_atomically(self, text: str) -> Path:
        """A throwaway copy validated with `xray run -test` -- never the real
        config path, so a failed validation never disturbs whatever Xray
        currently has loaded."""

        return _write_atomically(
            text,
            directory=self.validate_scratch_path.parent,
            target=self.validate_scratch_path,
            prefix=".xray_config_validate.",
        )

    def write_hysteria_config_atomically(self, text: str, target: PurePosixPath) -> Path:
        """Same handling as the Xray config: this file's `auth.userpass` map
        is a set of live credentials, so it is group-readable at most."""

        return _write_atomically(
            text,
            directory=Path(target).parent,
            target=Path(target),
            prefix=".hysteria_config.",
            mode=0o640,
        )

    def write_xray_config_atomically(self, text: str) -> Path:
        return _write_atomically(
            text,
            directory=self._xray_config_dir,
            target=self.xray_config_path,
            prefix=".xray_config.",
            # Group-readable, not world-readable -- this file's client list
            # is a set of VLESS bearer credentials, not public info like a
            # WireGuard public key. The deploying operator must put the
            # nebula-xray user in a group that can read xray_config_dir
            # (e.g. add it to nebula-agent's group) for this to actually
            # grant access; this mode alone does not.
            mode=0o640,
        )
