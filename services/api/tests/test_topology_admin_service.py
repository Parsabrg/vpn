import asyncio
from collections.abc import Iterable
from typing import cast
from uuid import uuid4

from nebula_api.db.engine import SessionFactory
from nebula_api.models.topology import Protocol, ProtocolProfile, VPNServer
from nebula_api.topology_admin.service import TopologyAdminService


class ScalarRows:
    def __init__(self, values: Iterable[object]) -> None:
        self._values = list(values)

    def all(self) -> list[object]:
        return self._values


class ScriptedSession:
    def __init__(self, *, scalars_values: Iterable[Iterable[object]] = ()) -> None:
        self.scalars_values = [list(values) for values in scalars_values]

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalars(self, _statement: object) -> ScalarRows:
        return ScalarRows(self.scalars_values.pop(0))


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        return self.sessions.pop(0)


def test_list_protocols_returns_empty_when_none_exist() -> None:
    session = ScriptedSession(scalars_values=[[]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocols())

    assert result == []


def test_list_protocols_maps_rows() -> None:
    row = Protocol(
        id=uuid4(),
        code="wireguard",
        display_name="WireGuard",
        engine="native_wireguard",
        is_user_selectable=True,
    )
    session = ScriptedSession(scalars_values=[[row]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocols())

    assert result[0].code == "wireguard"
    assert result[0].is_user_selectable is True


def test_list_protocol_profiles_returns_empty_when_none_exist() -> None:
    session = ScriptedSession(scalars_values=[[]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocol_profiles())

    assert result == []


def test_list_protocol_profiles_maps_rows() -> None:
    row = ProtocolProfile(
        id=uuid4(),
        protocol_id=uuid4(),
        code="wireguard-default",
        version=1,
        display_name="WireGuard default",
        state="draft",
        transport=None,
        transport_security=None,
        requires_udp=True,
        is_full_tunnel=True,
    )
    session = ScriptedSession(scalars_values=[[row]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocol_profiles())

    assert result[0].code == "wireguard-default"
    assert result[0].requires_udp is True


def test_list_vpn_servers_returns_empty_when_none_exist() -> None:
    session = ScriptedSession(scalars_values=[[]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_vpn_servers())

    assert result == []


def test_list_vpn_servers_maps_rows() -> None:
    row = VPNServer(
        id=uuid4(),
        code="ams-1",
        display_name="Amsterdam 1",
        state="disabled",
        agent_host="10.0.0.5",
        agent_port=9443,
        public_host="ams-1.example.test",
        maximum_devices=1000,
    )
    session = ScriptedSession(scalars_values=[[row]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_vpn_servers())

    assert result[0].code == "ams-1"
    assert result[0].public_host == "ams-1.example.test"
