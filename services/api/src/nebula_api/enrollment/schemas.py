"""Request and response bodies for node enrollment."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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
