"""Read-only listing of protocols, protocol profiles, and VPN servers."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select

from nebula_api.db.engine import SessionFactory
from nebula_api.models.topology import Protocol, ProtocolProfile, VPNServer


@dataclass(frozen=True, slots=True)
class ProtocolEntry:
    id: UUID
    code: str
    display_name: str
    engine: str
    is_user_selectable: bool


@dataclass(frozen=True, slots=True)
class ProtocolProfileEntry:
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


@dataclass(frozen=True, slots=True)
class VpnServerEntry:
    id: UUID
    code: str
    display_name: str
    state: str
    public_host: str
    maximum_devices: int


class TopologyAdminService:
    """Own read-only access to the (currently unpopulated) topology tables."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def list_protocols(self) -> list[ProtocolEntry]:
        async with self._session_factory() as session:
            rows = (await session.scalars(select(Protocol).order_by(Protocol.code))).all()
        return [
            ProtocolEntry(
                id=row.id,
                code=row.code,
                display_name=row.display_name,
                engine=row.engine,
                is_user_selectable=row.is_user_selectable,
            )
            for row in rows
        ]

    async def list_protocol_profiles(self) -> list[ProtocolProfileEntry]:
        async with self._session_factory() as session:
            rows = (
                await session.scalars(select(ProtocolProfile).order_by(ProtocolProfile.code))
            ).all()
        return [
            ProtocolProfileEntry(
                id=row.id,
                protocol_id=row.protocol_id,
                code=row.code,
                version=row.version,
                display_name=row.display_name,
                state=row.state,
                transport=row.transport,
                transport_security=row.transport_security,
                requires_udp=row.requires_udp,
                is_full_tunnel=row.is_full_tunnel,
            )
            for row in rows
        ]

    async def list_vpn_servers(self) -> list[VpnServerEntry]:
        async with self._session_factory() as session:
            rows = (await session.scalars(select(VPNServer).order_by(VPNServer.code))).all()
        return [
            VpnServerEntry(
                id=row.id,
                code=row.code,
                display_name=row.display_name,
                state=row.state,
                public_host=row.public_host,
                maximum_devices=row.maximum_devices,
            )
            for row in rows
        ]
