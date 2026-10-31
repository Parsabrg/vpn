"""Request and response bodies for node enrollment."""

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EnrollNodeRequest(BaseModel):
    """What a new VPS sends to join a deployment."""

    model_config = ConfigDict(extra="forbid")

    # The bearer credential. Refused uniformly whatever is wrong with it, so
    # this endpoint cannot be used to tell real tokens from invented ones.
    token: str = Field(min_length=1, max_length=256)

    # The node's certificate request. It supplies a public key and nothing
    # else that matters: the subject and the hostnames on the issued
    # certificate come from what the control plane already knows, because a
    # node able to name itself could name itself as another node.
    certificate_request: str = Field(min_length=1, max_length=8192)

    # Where clients reach this node for VPN traffic.
    public_host: str = Field(min_length=1, max_length=253)

    # Where the control plane reaches this node's agent, often a private
    # address on an internal network and so frequently not the public host.
    agent_host: str = Field(min_length=1, max_length=253)
    agent_port: int = Field(ge=1, le=65535)

    # The protocol profiles this node serves, by code, so it is offered for
    # them at once rather than after an administrator enables each by hand.
    protocol_profiles: list[str] = Field(default_factory=list, max_length=64)

    # The node's WireGuard range and its own address in it, when it serves
    # WireGuard. Without them no device can be given a WireGuard address here.
    wireguard_client_pool: IPv4Network | None = None
    wireguard_gateway_address: IPv4Address | None = None

    @model_validator(mode="after")
    def _wireguard_range_is_whole(self) -> Self:
        pool, gateway = self.wireguard_client_pool, self.wireguard_gateway_address
        if (pool is None) != (gateway is None):
            raise ValueError("send the WireGuard pool and gateway together")
        if pool is not None and gateway is not None:
            if not pool.is_private or gateway not in pool:
                raise ValueError("the WireGuard gateway must be in a private pool")
        return self


class EnrollNodeResponse(BaseModel):
    """What the node receives, and everything it needs to serve.

    No private key: the node generated its own and never sent it. What comes
    back is the certificate over the public key it did send, plus the
    authority to verify the control plane's own certificate against.
    """

    model_config = ConfigDict(extra="forbid")

    server_id: UUID
    label: str
    certificate: str
    ca_certificate: str


class EnrollmentTokenItem(BaseModel):
    """An outstanding token, without anything that could redeem it."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    label: str
    expires_at: datetime
    created_at: datetime


class MintEnrollmentTokenRequest(BaseModel):
    """An administrator adding a server from the panel."""

    model_config = ConfigDict(extra="forbid")

    # The new server's code and name: letters, digits and dashes, as the CLI.
    label: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")


class MintEnrollmentTokenResponse(BaseModel):
    """Shown once, to paste on the new server."""

    model_config = ConfigDict(extra="forbid")

    token: str
    label: str
    expires_at: datetime
    # Where the new server enrols: this API's public address.
    api_url: str
