import asyncio
from collections.abc import Iterable
from typing import cast
from uuid import UUID, uuid4

from nebula_api.db.engine import SessionFactory
from nebula_api.servers.service import ServerDiscoveryService


class MappingRows:
    def __init__(self, rows: Iterable[dict[str, object]]) -> None:
        self._rows = list(rows)

    def mappings(self) -> "MappingRows":
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class ScriptedSession:
    def __init__(self, rows: Iterable[dict[str, object]] = ()) -> None:
        self._rows = list(rows)

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, _statement: object) -> MappingRows:
        return MappingRows(self._rows)


class ScriptedFactory:
    def __init__(self, session: ScriptedSession) -> None:
        self._session = session

    def __call__(self) -> ScriptedSession:
        return self._session


USER_ID = UUID("11111111-1111-4111-8111-111111111111")


def test_returns_empty_when_no_rows_match() -> None:
    service = ServerDiscoveryService(
        cast(SessionFactory, ScriptedFactory(ScriptedSession(rows=[])))
    )

    result = asyncio.run(service.list_available_servers(USER_ID))

    assert result == []


def test_groups_multiple_profiles_under_one_server() -> None:
    protocol_id = uuid4()
    rows: list[dict[str, object]] = [
        {
            "server_code": "ams-1",
            "server_display_name": "Amsterdam 1",
            "public_host": "ams-1.example.test",
            "profile_code": "wireguard-default",
            "profile_display_name": "WireGuard default",
            "protocol_id": protocol_id,
        },
        {
            "server_code": "ams-1",
            "server_display_name": "Amsterdam 1",
            "public_host": "ams-1.example.test",
            "profile_code": "wireguard-fast",
            "profile_display_name": "WireGuard fast",
            "protocol_id": protocol_id,
        },
    ]
    service = ServerDiscoveryService(
        cast(SessionFactory, ScriptedFactory(ScriptedSession(rows=rows)))
    )

    result = asyncio.run(service.list_available_servers(USER_ID))

    assert len(result) == 1
    assert result[0].code == "ams-1"
    assert [profile.code for profile in result[0].profiles] == [
        "wireguard-default",
        "wireguard-fast",
    ]


def test_preserves_multiple_distinct_servers_in_order() -> None:
    rows: list[dict[str, object]] = [
        {
            "server_code": "ams-1",
            "server_display_name": "Amsterdam 1",
            "public_host": "ams-1.example.test",
            "profile_code": "wireguard-default",
            "profile_display_name": "WireGuard default",
            "protocol_id": uuid4(),
        },
        {
            "server_code": "nyc-1",
            "server_display_name": "New York 1",
            "public_host": "nyc-1.example.test",
            "profile_code": "wireguard-default",
            "profile_display_name": "WireGuard default",
            "protocol_id": uuid4(),
        },
    ]
    service = ServerDiscoveryService(
        cast(SessionFactory, ScriptedFactory(ScriptedSession(rows=rows)))
    )

    result = asyncio.run(service.list_available_servers(USER_ID))

    assert [entry.code for entry in result] == ["ams-1", "nyc-1"]
