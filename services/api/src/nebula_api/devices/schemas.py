"""Strict, bounded HTTP contracts for user-facing WireGuard peer provisioning."""

from uuid import UUID

from pydantic import Field

from nebula_api.auth.schemas import AuthModel

_PUBLIC_KEY_PATTERN = r"^[A-Za-z0-9+/]{43}=$"


class RequestPeerRequest(AuthModel):
    server_code: str = Field(min_length=1, max_length=64)
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
