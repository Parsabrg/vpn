"""Join across assignment/capability/permission tables for one user."""

from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import func, select

from nebula_api.db.engine import SessionFactory
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ServerProtocolCapability,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)
from nebula_api.models.types import (
    RUNNING_SERVER_STATES,
    CapabilityState,
    LifecycleState,
    ServerState,
)


@dataclass(frozen=True, slots=True)
class AvailableProfileEntry:
    code: str
    display_name: str
    protocol_id: UUID
    protocol_code: str
    # True for a profile's "-adblock" sibling -- lets the picker label it
    # distinctly (e.g. "VLESS XHTTP (Ad-block)") without the client having
    # to guess from the code's naming convention.
    ad_block: bool
    # See AvailableProfileItem in schemas.py for why these two travel with
    # the listing rather than only appearing at provisioning time.
    required_port: int | None = None
    requires_udp: bool = False
    # Which transports can be offered on the CDN route; see nebula_api/cdn.py.
    transport: str | None = None


@dataclass(frozen=True, slots=True)
class AvailableServerEntry:
    code: str
    display_name: str
    public_host: str
    profiles: list[AvailableProfileEntry] = field(default_factory=list)
    maintenance: bool = False


class ServerDiscoveryService:
    """Owns the same eligibility join `POST
    /v1/devices/{device_id}/wireguard-peer`'s `server_code` implicitly
    depends on, made discoverable instead of requiring out-of-band
    knowledge. A row is returned only when every one of these holds:

    - the caller has an active, unexpired `user_server_assignments` row for
      the server;
    - the server itself is `active`;
    - the server has an `enabled` `server_protocol_capabilities` row for the
      profile;
    - the caller has an `enabled`, unexpired `user_protocol_permissions`
      grant for that same profile.
    """

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def list_available_servers(
        self, user_id: UUID, *, include_maintenance: bool = False
    ) -> list[AvailableServerEntry]:
        """The servers this account may use.

        With [include_maintenance], servers under maintenance are listed too,
        flagged, so the app can say why one cannot be used rather than have
        it vanish. Off by default: an app from before the flag would list
        them as usable and fail to connect.
        """

        now = func.now()
        statement = (
            select(
                VPNServer.code.label("server_code"),
                VPNServer.display_name.label("server_display_name"),
                VPNServer.state.label("server_state"),
                VPNServer.public_host,
                ProtocolProfile.code.label("profile_code"),
                ProtocolProfile.display_name.label("profile_display_name"),
                ProtocolProfile.protocol_id,
                Protocol.code.label("protocol_code"),
                ProtocolProfile.ad_block,
                ProtocolProfile.required_port,
                ProtocolProfile.requires_udp,
                ProtocolProfile.transport,
            )
            .select_from(UserServerAssignment)
            .join(VPNServer, VPNServer.id == UserServerAssignment.vpn_server_id)
            .join(
                ServerProtocolCapability,
                ServerProtocolCapability.vpn_server_id == VPNServer.id,
            )
            .join(
                ProtocolProfile,
                ProtocolProfile.id == ServerProtocolCapability.protocol_profile_id,
            )
            .join(Protocol, Protocol.id == ProtocolProfile.protocol_id)
            .join(
                UserProtocolPermission,
                (UserProtocolPermission.protocol_profile_id == ProtocolProfile.id)
                & (UserProtocolPermission.user_id == user_id),
            )
            .where(
                UserServerAssignment.user_id == user_id,
                UserServerAssignment.state == LifecycleState.ACTIVE.value,
                (UserServerAssignment.expires_at.is_(None))
                | (UserServerAssignment.expires_at > now),
                VPNServer.state.in_(RUNNING_SERVER_STATES)
                if include_maintenance
                else VPNServer.state == ServerState.ACTIVE.value,
                ServerProtocolCapability.state == CapabilityState.ENABLED.value,
                UserProtocolPermission.state == CapabilityState.ENABLED.value,
                (UserProtocolPermission.expires_at.is_(None))
                | (UserProtocolPermission.expires_at > now),
            )
            .order_by(VPNServer.code, ProtocolProfile.code)
        )

        async with self._session_factory() as session:
            rows = (await session.execute(statement)).mappings().all()

        servers: dict[str, AvailableServerEntry] = {}
        order: list[str] = []
        for row in rows:
            server_code = row["server_code"]
            if server_code not in servers:
                servers[server_code] = AvailableServerEntry(
                    code=server_code,
                    display_name=row["server_display_name"],
                    public_host=row["public_host"],
                    maintenance=row["server_state"] == ServerState.MAINTENANCE.value,
                )
                order.append(server_code)
            servers[server_code].profiles.append(
                AvailableProfileEntry(
                    code=row["profile_code"],
                    display_name=row["profile_display_name"],
                    protocol_id=row["protocol_id"],
                    protocol_code=row["protocol_code"],
                    ad_block=row["ad_block"],
                    required_port=row["required_port"],
                    requires_udp=row["requires_udp"],
                    transport=row["transport"],
                )
            )
        return [servers[code] for code in order]
