"""Strict, bounded HTTP contracts for read-only topology listings."""

from uuid import UUID

from nebula_api.auth.schemas import AuthModel


class ProtocolListItem(AuthModel):
    id: UUID
    code: str
    display_name: str
    engine: str
    is_user_selectable: bool


class ProtocolListResponse(AuthModel):
    items: list[ProtocolListItem]


class ProtocolProfileListItem(AuthModel):
    id: UUID
    protocol_id: UUID
    code: str
    version: int
    display_name: str
    state: str
    transport: str | None
    transport_security: str | None
    requires_udp: bool
    is_full_tunnel: bool


class ProtocolProfileListResponse(AuthModel):
    items: list[ProtocolProfileListItem]


class VpnServerListItem(AuthModel):
    id: UUID
    code: str
    display_name: str
    state: str
    public_host: str
    maximum_devices: int


class VpnServerListResponse(AuthModel):
    items: list[VpnServerListItem]
