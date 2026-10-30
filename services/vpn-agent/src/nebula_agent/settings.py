"""Validated host-only configuration for the VPN agent."""

import base64
import re
from functools import lru_cache
from ipaddress import IPv4Address, ip_address, ip_network
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import (
    Field,
    IPvAnyAddress,
    IPvAnyInterface,
    IPvAnyNetwork,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from nebula_agent.drivers.hysteria_config_store import HysteriaServerProfile
from nebula_agent.drivers.xray_config_store import XrayInboundProfile

# Must match the `code` column seeded for each profile on the API side
# (services/api/src/nebula_api/topology_seed.py) exactly -- the agent has no
# DB access, so this is the one place these strings are kept in sync
# manually, same convention as drivers/base.py's OperationKind/TargetKind.
_XHTTP_PROFILE_CODE = "vless-xhttp-tls"
_GRPC_PROFILE_CODE = "vless-grpc-tls"
_WS_PROFILE_CODE = "vless-ws-tls"
_TCP_PROFILE_CODE = "vless-tcp-tls"
_HYSTERIA_PROFILE_CODE = "hysteria2"
_SS2022_PROFILE_CODE = "shadowsocks-2022"
_VLESSENC_PROFILE_CODE = "vless-enc"
_VMESS_RAW_PROFILE_CODE = "vmess-raw"
_VMESS_WS_PROFILE_CODE = "vmess-ws"

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")
_PUBLIC_ENDPOINT_PATTERN = re.compile(
    r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):(?P<port>\d{1,5})$"
)
_HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_XHTTP_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9/_-]{0,254}$")


def parse_dns_redirect(value: str) -> tuple[str, str] | None:
    """`address=host:port` as (address, "host:port"); None when malformed."""

    address, separator, target = value.partition("=")
    host, colon, port = target.rpartition(":")
    try:
        IPv4Address(address.strip())
        valid_port = 0 < int(port) < 65536
    except ValueError:
        return None
    if not separator or not colon or not host or not valid_port:
        return None
    return address.strip(), target.strip()


class Settings(BaseSettings):
    """Immutable agent settings; operation payloads cannot override these paths."""

    model_config = SettingsConfigDict(
        env_prefix="NEBULA_",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
    )

    env: Environment = "development"
    log_level: LogLevel = "INFO"
    wg_interface: str = "wg0"
    wg_server_private_key_file: PurePosixPath = PurePosixPath(
        "/run/nebula-secrets/wireguard_server_private_key"
    )
    xray_enabled: bool = False
    xray_driver: Literal["fake", "native"] = "fake"
    xray_binary: PurePosixPath = PurePosixPath("/usr/local/bin/xray")
    xray_config_dir: PurePosixPath = PurePosixPath("/etc/nebula/xray")
    xray_state_dir: PurePosixPath = PurePosixPath("/var/lib/nebula/xray")
    xray_validate_timeout_seconds: int = Field(default=10, ge=1, le=60)
    xray_apply_timeout_seconds: int = Field(default=20, ge=1, le=120)
    # The single XHTTP path shared by every client on this inbound -- VLESS
    # distinguishes clients by UUID (a bearer credential), not by path; a
    # per-client path would need a separate Xray inbound per device, which
    # XHTTP's stream settings don't support.
    xray_xhttp_path: str = "/xhttp"
    # Xray itself only ever binds loopback -- nginx terminates TLS on the
    # public :8445 and reverse-proxies here, exactly like the existing
    # :8444 API listener's relationship to this agent's own bind address.
    xray_local_listen_port: int = Field(default=8446, ge=1, le=65535)
    xray_public_host: str = "vpn.example.com"
    xray_public_port: int = Field(default=8445, ge=1, le=65535)
    xray_sni: str = "vpn.example.com"

    # --- Additional Xray transports (gRPC, WebSocket, raw TCP over TLS) ---
    # Unlike XHTTP, these bind directly and publicly -- Xray terminates TLS
    # itself here (no nginx in front), matching the pattern already proven
    # against this exact deployment's ISP by a separate, long-running Xray
    # setup on the same host. Each is individually opt-in (default off): a
    # fresh deployment shouldn't silently open three new public ports just
    # because xray_enabled=True.
    xray_grpc_enabled: bool = False
    xray_grpc_port: int = Field(default=8447, ge=1, le=65535)
    xray_grpc_service_name: str = "grpc"
    xray_ws_enabled: bool = False
    xray_ws_port: int = Field(default=8448, ge=1, le=65535)
    xray_ws_path: str = "/ws"
    xray_tcp_enabled: bool = False
    xray_tcp_port: int = Field(default=8449, ge=1, le=65535)
    # Shadowsocks-2022 on its own public TCP+UDP port, no TLS. The server key
    # is 16 random bytes in base64 (`openssl rand -base64 16`), required when
    # enabled; each client's own key comes from its UUID.
    xray_ss2022_enabled: bool = False
    xray_ss2022_port: int = Field(default=8451, ge=1, le=65535)
    xray_ss2022_server_key: str | None = None
    # VLESS Encryption on its own public TCP port, no TLS. The pair comes from
    # `xray vlessenc` (its ML-KEM-768 lines); both are required when enabled.
    xray_vlessenc_enabled: bool = False
    xray_vlessenc_port: int = Field(default=8453, ge=1, le=65535)
    xray_vlessenc_decryption: str | None = None
    xray_vlessenc_encryption: str | None = None
    # VMess with no TLS: one raw TCP inbound and one WebSocket inbound.
    xray_vmess_enabled: bool = False
    xray_vmess_port: int = Field(default=8454, ge=1, le=65535)
    xray_vmess_ws_port: int = Field(default=8455, ge=1, le=65535)
    xray_vmess_ws_path: str = "/vw"
    # Nebula's own resolver for Xray clients (roadmap 26,
    # infrastructure/adguard): "198.18.0.53=127.0.0.1:5354" sends what a
    # client asks of 198.18.0.53 on port 53 to the resolver on this host.
    # Empty: no redirect, and clients keep the resolver they were given.
    xray_dns_redirect: str = ""
    # Hysteria2 -- served by the standalone `hysteria` binary in its own
    # unit, NOT by Xray-core. Xray accepts the obfuscation setting and
    # silently discards it: a client offering a deliberately wrong Salamander
    # password authenticates successfully, so an inbound configured for
    # obfuscation has none and a client applying real Salamander cannot reach
    # it at all (docs/adr/0003). The flag keeps its name because it is what
    # deployments already set; only the implementation behind it changed.
    # Runs over QUIC/UDP, so its port must be opened for UDP specifically at
    # the firewall, unlike every other transport here (TCP-based).
    xray_hysteria_enabled: bool = False
    xray_hysteria_port: int = Field(default=8450, ge=1, le=65535)
    xray_hysteria_up_mbps: int = Field(default=100, ge=1, le=100_000)
    xray_hysteria_down_mbps: int = Field(default=100, ge=1, le=100_000)
    # Salamander obfuscation password (Xray-core's `udpmasks` finalmask, see
    # xray_config_store.py's XrayInboundProfile.hysteria_obfs_password) --
    # required whenever Hysteria2 is enabled (validated below): confirmed
    # live that plain, unobfuscated QUIC/Hysteria2 gets silently dropped by
    # this deployment's target ISP even though the port itself is reachable,
    # so shipping Hysteria2 without this would be shipping a profile that
    # provably doesn't work for the users it's meant for.
    xray_hysteria_obfs_password: str | None = None
    # Where the standalone binary's config is rendered, and the decoy an
    # unauthenticated prober is proxied to instead of meeting a silent port.
    xray_hysteria_config_file: PurePosixPath = PurePosixPath("/etc/nebula/hysteria/config.yaml")
    xray_hysteria_masquerade_url: str = "https://news.ycombinator.com"
    # Shared cert/key for every directly-TLS-terminating inbound above --
    # required (validated below) if any of the three enabled flags is set.
    # Reuses whatever Let's Encrypt cert the deploying host already has for
    # xray_public_host/xray_sni; one cert across several listeners.
    xray_tls_cert_file: PurePosixPath | None = None
    xray_tls_key_file: PurePosixPath | None = None
    # Where Xray's API listens. Loopback always -- the API has no
    # authentication of its own -- but it can be an address of its own
    # rather than 127.0.0.1, so the host can refuse it to local users with no
    # business there. The CI runner shares this host; see
    # docs/runbooks/deployment.md.
    xray_api_host: str = "127.0.0.1"
    # Add and remove clients through Xray's API instead of restarting it,
    # which drops every connection on the server. Off by default because it
    # turns on Xray's HandlerService, which can add users and whole inbounds:
    # switch it on only once nothing untrusted on the host can reach
    # xray_api_host.
    xray_live_client_updates: bool = False

    wg_driver: Literal["fake", "native"] = "fake"
    operation_ledger_file: PurePosixPath = PurePosixPath(
        "/var/lib/nebula/wireguard/operation_ledger.jsonl"
    )
    operation_ledger_max_entries: int = Field(default=10_000, ge=100, le=1_000_000)

    # --- WireGuard networking ---
    wg_binary: PurePosixPath = PurePosixPath("/usr/bin/wg")
    wg_state_dir: PurePosixPath = PurePosixPath("/var/lib/nebula/wireguard")
    wg_server_address: IPvAnyInterface = "10.77.0.1/24"  # type: ignore[assignment]
    wg_client_pool: IPvAnyNetwork = "10.77.0.0/24"  # type: ignore[assignment]
    wg_listen_port: int = Field(default=51820, ge=1, le=65535)
    wg_public_endpoint: str = "vpn.example.com:51820"
    wg_client_dns: IPvAnyAddress = "1.1.1.1"  # type: ignore[assignment]
    wg_client_allowed_ips: str = "0.0.0.0/0,::/0"
    wg_persistent_keepalive_seconds: int = Field(default=25, ge=1, le=3600)

    # --- Agent-side mTLS server identity ---
    agent_tls_cert_file: PurePosixPath = PurePosixPath("/run/nebula-secrets/agent_tls_cert")
    agent_tls_key_file: PurePosixPath = PurePosixPath("/run/nebula-secrets/agent_tls_key")
    agent_trusted_client_ca_file: PurePosixPath = PurePosixPath(
        "/run/nebula-secrets/agent_trusted_client_ca"
    )

    # --- Alerting ---
    # Read by nebula-healthcheck.service, which runs on the host rather than
    # in a container: an alerter that needs the API container up cannot report
    # that the API container is down. Optional so a deployment without mail
    # configured still runs every check and prints them; the command only
    # fails when it has something to report and nowhere to send it.
    alert_recipient: str | None = None
    # Required with alert_recipient: an address on a domain verified with the
    # mail provider. No default, since any default would be someone's domain.
    alert_sender: str | None = None
    alert_api_key_file: PurePosixPath | None = None
    alert_hostname: str = "vpn"
    # Survives reboots deliberately: /run is tmpfs, and losing this on every
    # boot would re-send every standing problem at boot time.
    alert_state_file: PurePosixPath = PurePosixPath("/var/lib/nebula/healthcheck.state")
    # An outside service that expects to hear from this host on a schedule.
    # Everything else reports *from* the VPS and so cannot report the VPS
    # being gone; this is the only check whose alert is produced by silence.
    # Treated as a secret: it is a capability URL, and anyone holding it can
    # keep the switch alive while the host is dead.
    deadman_url: str | None = None
    # Separate from alert_state_file: the reachability check runs on its own
    # cadence and reports a different kind of fact, so sharing one file would
    # let either one's transitions suppress the other's.
    reachability_state_file: PurePosixPath = PurePosixPath("/var/lib/nebula/reachability.state")

    # --- Listener binding ---
    # 0.0.0.0 is the Compose/dev default: inside that container's own network
    # namespace it is reachable only from sibling containers, never the host's
    # public interface (compose.yaml publishes no ports for this service).
    # The systemd unit (deploy/) overrides this to a loopback/private address,
    # since a real host's 0.0.0.0 would bind every interface including public
    # ones -- exactly what the threat model forbids.
    agent_bind_host: str = "0.0.0.0"  # noqa: S104 - dev-safe default, see comment above
    agent_bind_port: int = Field(default=9443, ge=1, le=65535)
    # Prometheus metrics on 127.0.0.1 only; 0 turns them off.
    agent_metrics_port: int = Field(default=9464, ge=0, le=65535)

    @field_validator("xray_dns_redirect")
    @classmethod
    def _dns_redirect_shape(cls, value: str) -> str:
        if value and parse_dns_redirect(value) is None:
            raise ValueError(
                "expected '<IPv4 address>=<host>:<port>', e.g. 198.18.0.53=127.0.0.1:5354"
            )
        return value

    @field_validator("wg_interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if not _INTERFACE_PATTERN.fullmatch(value):
            raise ValueError("must be a valid Linux interface name of at most 15 characters")
        return value

    @field_validator(
        "wg_server_private_key_file",
        "xray_binary",
        "xray_config_dir",
        "xray_state_dir",
        "operation_ledger_file",
        "wg_binary",
        "wg_state_dir",
        "agent_tls_cert_file",
        "agent_tls_key_file",
        "agent_trusted_client_ca_file",
    )
    @classmethod
    def require_absolute_host_path(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute():
            raise ValueError("host paths must be absolute")
        return value

    @field_validator("wg_public_endpoint")
    @classmethod
    def validate_public_endpoint(cls, value: str) -> str:
        match = _PUBLIC_ENDPOINT_PATTERN.fullmatch(value)
        if match is None:
            raise ValueError(
                "must be a bare host:port with no scheme, path, or shell metacharacters"
            )
        port = int(match.group("port"))
        if not (1 <= port <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return value

    @field_validator("wg_client_allowed_ips")
    @classmethod
    def validate_client_allowed_ips(cls, value: str) -> str:
        segments = value.split(",")
        if not segments or any(not segment for segment in segments):
            raise ValueError("must be a comma-separated list of CIDR networks")
        for segment in segments:
            try:
                ip_network(segment.strip(), strict=True)
            except ValueError as error:
                raise ValueError(f"invalid CIDR network {segment!r}: {error}") from error
        return value

    @field_validator("xray_api_host")
    @classmethod
    def validate_xray_api_host(cls, value: str) -> str:
        try:
            address = ip_address(value)
        except ValueError as error:
            raise ValueError("must be an IPv4 loopback address") from error
        if address.version != 4 or not address.is_loopback:
            raise ValueError("must be an IPv4 loopback address")
        return value

    @field_validator("xray_xhttp_path")
    @classmethod
    def validate_xray_xhttp_path(cls, value: str) -> str:
        if not _XHTTP_PATH_PATTERN.fullmatch(value):
            raise ValueError("must be an absolute path of safe characters")
        return value

    @field_validator("xray_public_host", "xray_sni")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        if not _HOSTNAME_PATTERN.fullmatch(value):
            raise ValueError("must be a bare hostname with no scheme, path, or port")
        return value

    @field_validator("xray_ws_path", "xray_vmess_ws_path")
    @classmethod
    def validate_xray_ws_path(cls, value: str) -> str:
        if not _XHTTP_PATH_PATTERN.fullmatch(value):
            raise ValueError("must be an absolute path of safe characters")
        return value

    @field_validator("xray_grpc_service_name")
    @classmethod
    def validate_xray_grpc_service_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("must be a safe gRPC service name of at most 64 characters")
        return value

    @field_validator("xray_tls_cert_file", "xray_tls_key_file")
    @classmethod
    def require_absolute_xray_tls_path(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        if value is not None and not value.is_absolute():
            raise ValueError("host paths must be absolute")
        return value

    @model_validator(mode="after")
    def require_server_address_within_client_pool(self) -> Self:
        if self.wg_server_address.ip not in self.wg_client_pool:
            raise ValueError("wg_server_address must fall inside wg_client_pool")
        return self

    @model_validator(mode="after")
    def require_tls_material_for_direct_terminating_transports(self) -> Self:
        if (
            self.xray_grpc_enabled
            or self.xray_ws_enabled
            or self.xray_tcp_enabled
            or self.xray_hysteria_enabled
        ) and (self.xray_tls_cert_file is None or self.xray_tls_key_file is None):
            raise ValueError(
                "xray_tls_cert_file and xray_tls_key_file are required when any of "
                "xray_grpc_enabled/xray_ws_enabled/xray_tcp_enabled/xray_hysteria_enabled is set"
            )
        return self

    @model_validator(mode="after")
    def require_obfs_password_for_hysteria(self) -> Self:
        if self.xray_hysteria_enabled and not self.xray_hysteria_obfs_password:
            raise ValueError(
                "xray_hysteria_obfs_password is required when xray_hysteria_enabled is set"
            )
        return self

    @model_validator(mode="after")
    def require_ss2022_server_key(self) -> Self:
        if not self.xray_ss2022_enabled:
            return self
        try:
            raw = base64.b64decode(self.xray_ss2022_server_key or "", validate=True)
        except ValueError as error:
            raise ValueError("xray_ss2022_server_key must be base64") from error
        if len(raw) != 16:
            raise ValueError(
                "xray_ss2022_server_key must be 16 bytes in base64 (openssl rand -base64 16) "
                "when xray_ss2022_enabled is set"
            )
        return self

    @model_validator(mode="after")
    def require_vlessenc_pair(self) -> Self:
        if self.xray_vlessenc_enabled and not (
            (self.xray_vlessenc_decryption or "").startswith("mlkem768x25519plus.")
            and (self.xray_vlessenc_encryption or "").startswith("mlkem768x25519plus.")
        ):
            raise ValueError(
                "xray_vlessenc_decryption and xray_vlessenc_encryption (an `xray vlessenc` "
                "mlkem768x25519plus pair) are required when xray_vlessenc_enabled is set"
            )
        return self

    @model_validator(mode="after")
    def require_distinct_xray_ports(self) -> Self:
        ports = [self.xray_local_listen_port, self.xray_public_port, self.agent_bind_port]
        if self.xray_grpc_enabled:
            ports.append(self.xray_grpc_port)
        if self.xray_ws_enabled:
            ports.append(self.xray_ws_port)
        if self.xray_tcp_enabled:
            ports.append(self.xray_tcp_port)
        if self.xray_hysteria_enabled:
            ports.append(self.xray_hysteria_port)
        if self.xray_ss2022_enabled:
            ports.append(self.xray_ss2022_port)
        if self.xray_vlessenc_enabled:
            ports.append(self.xray_vlessenc_port)
        if self.xray_vmess_enabled:
            ports.extend((self.xray_vmess_port, self.xray_vmess_ws_port))
        if len(ports) != len(set(ports)):
            raise ValueError("xray/agent listener ports must all be distinct")
        return self

    def build_xray_inbound_profiles(self) -> tuple[XrayInboundProfile, ...]:
        """The static set of Xray inbounds this deployment should render,
        independent of which clients currently exist -- mirrors how the
        WireGuard interface's own shape (listen port, address pool) is pure
        Settings, not DB-driven. XHTTP is unconditional (already deployed,
        loopback-only, nginx-fronted); the other three are individually
        opt-in and bind/terminate TLS directly."""

        profiles = [
            XrayInboundProfile(
                protocol_profile_code=_XHTTP_PROFILE_CODE,
                transport="xhttp",
                listen="127.0.0.1",
                port=self.xray_local_listen_port,
                security="none",
                xhttp_path=self.xray_xhttp_path,
            )
        ]
        if self.xray_grpc_enabled:
            profiles.append(
                XrayInboundProfile(
                    protocol_profile_code=_GRPC_PROFILE_CODE,
                    transport="grpc",
                    listen="0.0.0.0",  # noqa: S104 - deliberately public, TLS-terminated here
                    port=self.xray_grpc_port,
                    security="tls",
                    grpc_service_name=self.xray_grpc_service_name,
                )
            )
        if self.xray_ws_enabled:
            profiles.append(
                XrayInboundProfile(
                    protocol_profile_code=_WS_PROFILE_CODE,
                    transport="websocket",
                    listen="0.0.0.0",  # noqa: S104 - deliberately public, TLS-terminated here
                    port=self.xray_ws_port,
                    security="tls",
                    ws_path=self.xray_ws_path,
                )
            )
        if self.xray_tcp_enabled:
            profiles.append(
                XrayInboundProfile(
                    protocol_profile_code=_TCP_PROFILE_CODE,
                    transport="raw",
                    listen="0.0.0.0",  # noqa: S104 - deliberately public, TLS-terminated here
                    port=self.xray_tcp_port,
                    security="tls",
                )
            )
        if self.xray_ss2022_enabled:
            profiles.append(
                XrayInboundProfile(
                    protocol_profile_code=_SS2022_PROFILE_CODE,
                    transport="raw",
                    listen="0.0.0.0",  # noqa: S104 - deliberately public, its own encryption
                    port=self.xray_ss2022_port,
                    security="none",
                    ss2022_server_key=self.xray_ss2022_server_key,
                )
            )
        if self.xray_vlessenc_enabled:
            profiles.append(
                XrayInboundProfile(
                    protocol_profile_code=_VLESSENC_PROFILE_CODE,
                    transport="raw",
                    listen="0.0.0.0",  # noqa: S104 - deliberately public, its own encryption
                    port=self.xray_vlessenc_port,
                    security="none",
                    vless_decryption=self.xray_vlessenc_decryption,
                    vless_encryption=self.xray_vlessenc_encryption,
                )
            )
        if self.xray_vmess_enabled:
            profiles.append(
                XrayInboundProfile(
                    protocol_profile_code=_VMESS_RAW_PROFILE_CODE,
                    transport="raw",
                    listen="0.0.0.0",  # noqa: S104 - deliberately public, its own encryption
                    port=self.xray_vmess_port,
                    security="none",
                    vmess=True,
                )
            )
            profiles.append(
                XrayInboundProfile(
                    protocol_profile_code=_VMESS_WS_PROFILE_CODE,
                    transport="websocket",
                    listen="0.0.0.0",  # noqa: S104 - deliberately public, its own encryption
                    port=self.xray_vmess_ws_port,
                    security="none",
                    ws_path=self.xray_vmess_ws_path,
                    vmess=True,
                )
            )
        # Hysteria2 is deliberately absent here: it is no longer an Xray
        # inbound. See hysteria_server_profile() below.
        return tuple(profiles)

    def hysteria_server_profile(self) -> HysteriaServerProfile | None:
        """The standalone Hysteria2 server's shape, or None when disabled.

        Separate from xray_inbound_profiles() because this transport is
        served by a different binary in a different unit. Xray-core accepts
        the obfuscation setting and silently discards it -- a client with a
        deliberately wrong Salamander password authenticates -- so an
        inbound configured for obfuscation has none. docs/adr/0003 has the
        measurements.
        """

        if not self.xray_hysteria_enabled:
            return None
        obfs = self.xray_hysteria_obfs_password
        cert = self.xray_tls_cert_file
        key = self.xray_tls_key_file
        if obfs is None or cert is None or key is None:
            # The model validators below already reject this combination at
            # construction, so reaching here means a validator was removed
            # rather than that a deployment is misconfigured -- worth failing
            # loudly instead of rendering a config with "None" in it.
            raise ValueError(
                "hysteria enabled without obfs password or TLS cert/key; "
                "the Settings validators should have rejected this"
            )
        return HysteriaServerProfile(
            protocol_profile_code=_HYSTERIA_PROFILE_CODE,
            port=self.xray_hysteria_port,
            tls_cert_file=str(cert),
            tls_key_file=str(key),
            obfs_password=obfs,
            up_mbps=self.xray_hysteria_up_mbps,
            down_mbps=self.xray_hysteria_down_mbps,
            masquerade_url=self.xray_hysteria_masquerade_url,
        )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable host settings instance."""

    return Settings()
