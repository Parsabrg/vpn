"""Strict, bounded HTTP contracts for user-facing server discovery."""

from uuid import UUID

from nebula_api.auth.schemas import AuthModel


class AvailableProfileItem(AuthModel):
    code: str
    display_name: str
    protocol_id: UUID
    protocol_code: str
    ad_block: bool

    # Where this profile is actually reached. Published so a client can
    # measure a server before choosing it -- the port is only otherwise
    # known after provisioning, which registers a device and starts
    # counting traffic, so a client that had to connect in order to find
    # out how far away a server is could not offer the choice at all.
    #
    # Nothing secret: it is the port the client dials a moment later, and
    # anybody scanning the host sees the same thing.
    required_port: int | None = None

    # UDP profiles cannot be measured the way TCP ones can -- a UDP socket
    # accepts a connect() and sends into the void whether or not anything
    # is listening, so a "reachable" result would mean nothing. Flagged so
    # the client reports them unmeasured rather than fast.
    requires_udp: bool = False


class AvailableServerItem(AuthModel):
    code: str
    display_name: str
    public_host: str
    profiles: list[AvailableProfileItem]
    # Listed only when the app asks for it (include_maintenance); takes no
    # new connections until it is active again.
    maintenance: bool = False


class AvailableServerListResponse(AuthModel):
    items: list[AvailableServerItem]
