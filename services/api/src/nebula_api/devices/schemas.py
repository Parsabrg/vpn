"""Strict, bounded HTTP contracts for user-facing WireGuard peer provisioning."""

from uuid import UUID

from pydantic import Field

from nebula_api.auth.schemas import AuthModel

_PUBLIC_KEY_PATTERN = r"^[A-Za-z0-9+/]{43}=$"
# Matches services/vpn-agent's own _PROFILE_CODE_PATTERN exactly.
_PROFILE_CODE_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"


class RequestPeerRequest(AuthModel):
    server_code: str = Field(min_length=1, max_length=64)
    # e.g. "wireguard-native", "wireguard-adblock" -- which WireGuard
    # sibling the client is choosing, mirroring the manual picker UX used
    # for every Xray transport.
    protocol_profile_code: str = Field(min_length=1, max_length=64, pattern=_PROFILE_CODE_PATTERN)
    public_key: str = Field(min_length=44, max_length=44, pattern=_PUBLIC_KEY_PATTERN)


class RevokePeerRequest(AuthModel):
    server_code: str = Field(min_length=1, max_length=64)


class WireGuardPeerResponse(AuthModel):
    peer_id: UUID
    assigned_address: str
    server_public_key: str
    listen_port: int
    public_endpoint: str
    client_dns: str
    client_allowed_ips: str
    persistent_keepalive_seconds: int


class RequestXrayClientRequest(AuthModel):
    server_code: str = Field(min_length=1, max_length=64)
    # e.g. "vless-xhttp-tls", "vless-grpc-tls", "vless-ws-tls",
    # "vless-tcp-tls", "hysteria2" -- which of the server's enabled Xray
    # transports the client is choosing, mirroring the manual picker UX
    # already used for WireGuard vs VLESS.
    protocol_profile_code: str = Field(min_length=1, max_length=64, pattern=_PROFILE_CODE_PATTERN)


class RevokeXrayClientRequest(AuthModel):
    server_code: str = Field(min_length=1, max_length=64)
    protocol_profile_code: str = Field(min_length=1, max_length=64, pattern=_PROFILE_CODE_PATTERN)


class XrayClientResponse(AuthModel):
    client_id: UUID
    uuid: UUID
    server_address: str
    port: int
    sni: str
    transport: str
    transport_security: str
    path: str | None = None
    service_name: str | None = None
    obfs_password: str | None = None
    # Shadowsocks-2022 only; "vless" for every other Xray profile.
    protocol: str = "vless"
    method: str | None = None
    password: str | None = None
    # VLESS Encryption only; "none" (unset) for every other VLESS profile.
    encryption: str | None = None
    ad_block: bool = False
    # Set for a tunnel through Cloudflare: Xray's echConfigList. See cdn.py.
    ech_config_list: str | None = None
    # The deployment's own resolver, when it runs one (roadmap 26). A list,
    # as the app reads it (and as the WireGuard response's string is not).
    client_dns: list[str] = Field(default_factory=list)
