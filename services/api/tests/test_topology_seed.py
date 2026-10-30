import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import nebula_api.topology_seed as topology_seed_module
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import User
from nebula_api.models.operations import AuditLog
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ServerProtocolCapability,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)
from nebula_api.models.types import CapabilityState, LifecycleState, ProfileState
from nebula_api.topology_seed import (
    CreateServerResult,
    CreateServerStatus,
    EnableCapabilityStatus,
    GrantAccessStatus,
    SeedProtocolStatus,
    create_vpn_server,
    disable_server_capability,
    enable_server_capability,
    grant_user_server_access,
    seed_direct_protocols,
    seed_hysteria2_adblock_protocol,
    seed_hysteria2_protocol,
    seed_ss2022_adblock_protocol,
    seed_ss2022_protocol,
    seed_vless_grpc_protocol,
    seed_vless_tcp_protocol,
    seed_vless_ws_protocol,
    seed_vless_xhttp_adblock_protocol,
    seed_vless_xhttp_protocol,
    seed_wireguard_adblock_profile,
    seed_wireguard_protocol,
)


def fake_scope_for(
    session: AsyncSession,
) -> Callable[[SessionFactory], AbstractAsyncContextManager[AsyncSession]]:
    @asynccontextmanager
    async def fake_scope(_factory: SessionFactory) -> AsyncIterator[AsyncSession]:
        yield session

    return fake_scope


class _rows:
    """What `session.scalars(...)` returns: something with `.all()`."""

    def __init__(self, items: list[object]) -> None:
        self._items = items

    def all(self) -> list[object]:
        return self._items


def _assign_ids_in_add_order(session: MagicMock) -> AsyncMock:
    """Every session.add(row) gets a fresh id assigned on the next flush(),
    in call order -- mirrors real autoincrement-on-flush ORM behavior."""

    assigned: set[int] = set()

    async def _flush() -> None:
        for index, call in enumerate(session.add.call_args_list):
            if index in assigned:
                continue
            row = call.args[0]
            if getattr(row, "id", None) is None:
                row.id = uuid4()
            assigned.add(index)

    return AsyncMock(side_effect=_flush)


# --- seed_wireguard_protocol ---------------------------------------------


def test_seed_wireguard_protocol_creates_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_wireguard_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    protocol = cast(Protocol, session.add.call_args_list[0].args[0])
    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    audit = cast(AuditLog, session.add.call_args_list[2].args[0])
    assert protocol.code == "wireguard"
    assert profile.state == ProfileState.IMPLEMENTED.value
    assert profile.protocol_id == protocol.id
    assert audit.event_code == "profile_changed"
    assert audit.actor_kind == "bootstrap"


def test_seed_wireguard_protocol_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    existing_protocol = MagicMock(spec=Protocol)
    existing_protocol.id = uuid4()
    existing_profile = MagicMock(spec=ProtocolProfile)
    existing_profile.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[existing_protocol, existing_profile])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_wireguard_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.ALREADY_SEEDED
    assert result.protocol_id == existing_protocol.id
    assert result.protocol_profile_id == existing_profile.id
    session.add.assert_not_called()


# --- seed_vless_xhttp_protocol ---------------------------------------------


def test_seed_vless_xhttp_protocol_creates_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_vless_xhttp_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    protocol = cast(Protocol, session.add.call_args_list[0].args[0])
    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    audit = cast(AuditLog, session.add.call_args_list[2].args[0])
    assert protocol.code == "vless"
    assert protocol.engine == "xray"
    assert profile.code == "vless-xhttp-tls"
    assert profile.transport == "xhttp"
    assert profile.transport_security == "tls"
    assert profile.template_key == "vless_xhttp_tls"
    assert profile.required_port == 8445
    assert profile.requires_udp is False
    assert profile.is_full_tunnel is True
    assert profile.state == ProfileState.IMPLEMENTED.value
    assert profile.protocol_id == protocol.id
    assert audit.event_code == "profile_changed"
    assert audit.actor_kind == "bootstrap"


def test_seed_vless_xhttp_protocol_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    existing_protocol = MagicMock(spec=Protocol)
    existing_protocol.id = uuid4()
    existing_profile = MagicMock(spec=ProtocolProfile)
    existing_profile.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[existing_protocol, existing_profile])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_vless_xhttp_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.ALREADY_SEEDED
    assert result.protocol_id == existing_protocol.id
    assert result.protocol_profile_id == existing_profile.id
    session.add.assert_not_called()


def test_seed_vless_xhttp_protocol_adds_a_profile_to_an_already_existing_protocol_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Protocol row can already exist with zero or more OTHER profiles
    under it (e.g. "vless" already carries a gRPC profile) -- seeding XHTTP
    should add the XHTTP profile, not error, mirroring how a second
    transport gets added to an already-seeded protocol."""

    existing_protocol = MagicMock(spec=Protocol)
    existing_protocol.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[existing_protocol, None])
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_vless_xhttp_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    assert result.protocol_id == existing_protocol.id
    profile = cast(ProtocolProfile, session.add.call_args_list[0].args[0])
    assert profile.code == "vless-xhttp-tls"
    assert profile.protocol_id == existing_protocol.id


# --- seed_vless_grpc_protocol / seed_hysteria2_protocol --------------------


def test_seed_vless_grpc_protocol_creates_a_new_protocol_and_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_vless_grpc_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    protocol = cast(Protocol, session.add.call_args_list[0].args[0])
    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    assert protocol.code == "vless"
    assert protocol.engine == "xray"
    assert profile.code == "vless-grpc-tls"
    assert profile.transport == "grpc"
    assert profile.required_port == 8447
    assert profile.requires_udp is False


def test_seed_vless_grpc_protocol_reuses_an_already_seeded_vless_protocol_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """gRPC's Protocol row ("vless") may already exist from seeding XHTTP
    first -- only the gRPC-specific ProtocolProfile row should be added."""

    existing_protocol = MagicMock(spec=Protocol)
    existing_protocol.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[existing_protocol, None])
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_vless_grpc_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    assert result.protocol_id == existing_protocol.id
    assert session.add.call_count == 2  # profile, then its audit log
    profile = cast(ProtocolProfile, session.add.call_args_list[0].args[0])
    assert profile.code == "vless-grpc-tls"
    assert profile.protocol_id == existing_protocol.id


def test_seed_vless_grpc_protocol_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    existing_protocol = MagicMock(spec=Protocol)
    existing_protocol.id = uuid4()
    existing_profile = MagicMock(spec=ProtocolProfile)
    existing_profile.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[existing_protocol, existing_profile])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_vless_grpc_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.ALREADY_SEEDED
    session.add.assert_not_called()


def test_seed_vless_ws_and_tcp_protocols_create_their_own_profiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for seed_function, expected_code, expected_transport, expected_port in (
        (seed_vless_ws_protocol, "vless-ws-tls", "websocket", 8448),
        (seed_vless_tcp_protocol, "vless-tcp-tls", "raw", 8449),
    ):
        session = MagicMock(spec=AsyncSession)
        session.execute = AsyncMock()
        session.scalar = AsyncMock(return_value=None)
        session.flush = _assign_ids_in_add_order(session)
        monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

        result = asyncio.run(seed_function(cast(SessionFactory, MagicMock())))

        assert result.status is SeedProtocolStatus.CREATED
        profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
        assert profile.code == expected_code
        assert profile.transport == expected_transport
        assert profile.required_port == expected_port


def test_seed_hysteria2_protocol_creates_its_own_protocol_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_hysteria2_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    protocol = cast(Protocol, session.add.call_args_list[0].args[0])
    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    assert protocol.code == "hysteria2"
    # Not "xray": Xray-core accepts Hysteria2's Salamander obfuscation setting
    # and silently discards it, so this transport is served by the reference
    # binary in its own unit (docs/adr/0003). The column is read by people
    # rather than by dispatch, which is what makes a wrong value harmful.
    assert protocol.engine == "hysteria"
    assert profile.code == "hysteria2"
    assert profile.transport == "hysteria"
    assert profile.required_port == 8450
    assert profile.requires_udp is True


# --- ad_block sibling profiles ----------------------------------------------


def test_seed_vless_xhttp_adblock_protocol_redirects_to_the_real_agent_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_vless_xhttp_adblock_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    assert profile.code == "vless-xhttp-tls-adblock"
    assert profile.ad_block is True
    assert profile.agent_profile_code == "vless-xhttp-tls"
    assert profile.transport == "xhttp"


def test_seed_hysteria2_adblock_protocol_redirects_to_the_real_agent_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_hysteria2_adblock_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    protocol = cast(Protocol, session.add.call_args_list[0].args[0])
    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    assert protocol.code == "hysteria2"
    assert profile.code == "hysteria2-adblock"
    assert profile.ad_block is True
    assert profile.agent_profile_code == "hysteria2"
    assert profile.requires_udp is True


def test_seed_wireguard_adblock_profile_requires_wireguard_already_seeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    with pytest.raises(ValueError, match="no WireGuard protocol is seeded"):
        asyncio.run(seed_wireguard_adblock_profile(cast(SessionFactory, MagicMock())))


def test_seed_wireguard_adblock_profile_adds_a_second_profile_with_no_agent_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing_protocol = MagicMock(spec=Protocol)
    existing_protocol.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[existing_protocol, None])
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_wireguard_adblock_profile(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    profile = cast(ProtocolProfile, session.add.call_args_list[0].args[0])
    assert profile.code == "wireguard-native-adblock"
    assert profile.ad_block is True
    # WireGuard has no per-profile agent inbound to redirect to at all --
    # unlike every Xray ad_block sibling, this stays unset.
    assert profile.agent_profile_code is None
    assert profile.protocol_id == existing_protocol.id


def test_seed_wireguard_adblock_profile_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    existing_protocol = MagicMock(spec=Protocol)
    existing_protocol.id = uuid4()
    existing_profile = MagicMock(spec=ProtocolProfile)
    existing_profile.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[existing_protocol, existing_profile])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_wireguard_adblock_profile(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.ALREADY_SEEDED
    session.add.assert_not_called()


# --- enable_server_capability ------------------------------------------------


def test_enable_server_capability_creates_a_new_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MagicMock(spec=VPNServer)
    server.id = uuid4()
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = uuid4()
    profile.state = ProfileState.IMPLEMENTED.value
    profile.version = 1

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[server, profile, None])
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(
        enable_server_capability(
            cast(SessionFactory, MagicMock()),
            server_code="vps-1",
            protocol_profile_code="hysteria2",
        )
    )

    assert result.status is EnableCapabilityStatus.CREATED
    capability = cast(ServerProtocolCapability, session.add.call_args_list[0].args[0])
    assert capability.vpn_server_id == server.id
    assert capability.protocol_profile_id == profile.id
    assert capability.state == CapabilityState.ENABLED.value


def test_enable_server_capability_is_a_no_op_when_already_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MagicMock(spec=VPNServer)
    server.id = uuid4()
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = uuid4()
    profile.state = ProfileState.IMPLEMENTED.value
    existing_capability = MagicMock(spec=ServerProtocolCapability)
    existing_capability.id = uuid4()
    existing_capability.state = CapabilityState.ENABLED.value

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[server, profile, existing_capability])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(
        enable_server_capability(
            cast(SessionFactory, MagicMock()),
            server_code="vps-1",
            protocol_profile_code="hysteria2",
        )
    )

    assert result.status is EnableCapabilityStatus.ALREADY_ENABLED
    session.add.assert_not_called()


def test_enable_server_capability_re_enables_a_disabled_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MagicMock(spec=VPNServer)
    server.id = uuid4()
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = uuid4()
    profile.state = ProfileState.IMPLEMENTED.value
    existing_capability = MagicMock(spec=ServerProtocolCapability)
    existing_capability.id = uuid4()
    existing_capability.state = CapabilityState.DISABLED.value

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[server, profile, existing_capability])
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(
        enable_server_capability(
            cast(SessionFactory, MagicMock()),
            server_code="vps-1",
            protocol_profile_code="hysteria2",
        )
    )

    assert result.status is EnableCapabilityStatus.RE_ENABLED
    assert existing_capability.state == CapabilityState.ENABLED.value


def test_disable_server_capability_stops_offering_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A protocol turned off on the server must not be handed to clients.
    capability = MagicMock(spec=ServerProtocolCapability)
    capability.state = CapabilityState.ENABLED.value
    session = MagicMock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=capability)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    changed = asyncio.run(
        disable_server_capability(
            cast(SessionFactory, MagicMock()),
            server_code="vps-1",
            protocol_profile_code="vmess-raw",
        )
    )

    assert changed is True
    assert capability.state == CapabilityState.DISABLED.value


def test_disable_server_capability_is_a_no_op_when_not_offered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=None)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    assert (
        asyncio.run(
            disable_server_capability(
                cast(SessionFactory, MagicMock()),
                server_code="vps-1",
                protocol_profile_code="vmess-raw",
            )
        )
        is False
    )


def test_enable_server_capability_rejects_an_unknown_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    with pytest.raises(ValueError, match="no VPN server found"):
        asyncio.run(
            enable_server_capability(
                cast(SessionFactory, MagicMock()),
                server_code="missing",
                protocol_profile_code="hysteria2",
            )
        )


def test_enable_server_capability_rejects_an_unimplemented_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = MagicMock(spec=VPNServer)
    server.id = uuid4()

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[server, None])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    with pytest.raises(ValueError, match="no implemented protocol profile found"):
        asyncio.run(
            enable_server_capability(
                cast(SessionFactory, MagicMock()),
                server_code="vps-1",
                protocol_profile_code="hysteria2",
            )
        )


# --- create_vpn_server -----------------------------------------------------


async def _create_server(
    session_factory: SessionFactory,
    *,
    code: str = "vps-1",
    display_name: str = "VPS 1",
    agent_host: str = "vps1.internal",
    agent_port: int = 9443,
    public_host: str = "vpn1.example.com",
    wireguard_client_pool: str | None = "10.77.0.0/24",
    wireguard_gateway_address: str | None = "10.77.0.1",
    maximum_devices: int = 1000,
    state: str = "active",
) -> CreateServerResult:
    return await create_vpn_server(
        session_factory,
        code=code,
        display_name=display_name,
        agent_host=agent_host,
        agent_port=agent_port,
        public_host=public_host,
        wireguard_client_pool=wireguard_client_pool,
        wireguard_gateway_address=wireguard_gateway_address,
        maximum_devices=maximum_devices,
        state=state,
    )


def test_create_vpn_server_creates_and_enables_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = MagicMock(spec=Protocol)
    protocol.id = uuid4()
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = uuid4()
    profile.version = 1

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[None, protocol, profile])
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(_create_server(cast(SessionFactory, MagicMock())))

    assert result.status is CreateServerStatus.CREATED
    server = cast(VPNServer, session.add.call_args_list[0].args[0])
    capability = cast(ServerProtocolCapability, session.add.call_args_list[1].args[0])
    assert server.code == "vps-1"
    assert capability.vpn_server_id == server.id
    assert capability.protocol_profile_id == profile.id
    assert capability.state == CapabilityState.ENABLED.value
    assert result.vpn_server_id == server.id


def test_create_vpn_server_rejects_a_duplicate_code(monkeypatch: pytest.MonkeyPatch) -> None:
    existing = MagicMock(spec=VPNServer)
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=existing)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    with pytest.raises(ValueError, match="already exists"):
        asyncio.run(_create_server(cast(SessionFactory, MagicMock())))


def test_create_vpn_server_requires_the_protocol_to_be_seeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[None, None])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    with pytest.raises(ValueError, match="seed-wireguard-protocol"):
        asyncio.run(_create_server(cast(SessionFactory, MagicMock())))


def test_create_vpn_server_requires_an_implemented_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = MagicMock(spec=Protocol)
    protocol.id = uuid4()
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[None, protocol, None])
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    with pytest.raises(ValueError, match="implemented"):
        asyncio.run(_create_server(cast(SessionFactory, MagicMock())))


# --- grant_user_server_access ----------------------------------------------


def test_grant_user_server_access_creates_permission_and_assignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = MagicMock(spec=User)
    user.id = uuid4()
    server = MagicMock(spec=VPNServer)
    server.id = uuid4()
    protocol = MagicMock(spec=Protocol)
    protocol.id = uuid4()
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = uuid4()

    second = MagicMock(spec=ProtocolProfile)
    second.id = uuid4()
    second.code = "vless-xhttp-tls"
    profile.code = "hysteria2"

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    # order: user, server, then one existing-permission lookup per profile,
    # then the existing assignment.
    session.scalar = AsyncMock(side_effect=[user, server, None, None, None])
    # Every profile the server offers, which is what grants now follow.
    session.scalars = AsyncMock(return_value=_rows([profile, second]))
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(
        grant_user_server_access(
            cast(SessionFactory, MagicMock()),
            user_email="owner@example.com",
            server_code="vps-1",
        )
    )

    assert result.status is GrantAccessStatus.GRANTED
    assert result.user_id == user.id
    # One permission per profile the server offers, not one in total. This
    # is the whole point: granting WireGuard alone left the other protocols
    # needing hand-written SQL, and nothing said so.
    permissions = [
        added
        for call in session.add.call_args_list
        for added in call.args
        if isinstance(added, UserProtocolPermission)
    ]
    assignments = [
        added
        for call in session.add.call_args_list
        for added in call.args
        if isinstance(added, UserServerAssignment)
    ]
    assert len(permissions) == 2
    assert all(p.state == CapabilityState.ENABLED.value for p in permissions)
    assert len(assignments) == 1
    assert assignments[0].state == LifecycleState.ACTIVE.value
    assert result.profile_codes == ["hysteria2", "vless-xhttp-tls"]


def test_grant_user_server_access_reactivates_a_revoked_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = MagicMock(spec=User)
    user.id = uuid4()
    server = MagicMock(spec=VPNServer)
    server.id = uuid4()
    protocol = MagicMock(spec=Protocol)
    protocol.id = uuid4()
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = uuid4()
    existing_permission = MagicMock(spec=UserProtocolPermission)
    existing_permission.id = uuid4()
    existing_permission.state = CapabilityState.DISABLED.value
    existing_assignment = MagicMock(spec=UserServerAssignment)
    existing_assignment.id = uuid4()
    existing_assignment.state = LifecycleState.REVOKED.value

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(side_effect=[user, server, existing_permission, existing_assignment])
    session.scalars = AsyncMock(return_value=_rows([profile]))
    session.flush = AsyncMock()
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(
        grant_user_server_access(
            cast(SessionFactory, MagicMock()),
            user_email="owner@example.com",
            server_code="vps-1",
        )
    )

    assert result.status is GrantAccessStatus.GRANTED
    assert existing_permission.state == CapabilityState.ENABLED.value
    assert existing_permission.revoked_at is None
    assert existing_assignment.state == LifecycleState.ACTIVE.value
    assert existing_assignment.revoked_at is None


def test_grant_user_server_access_rejects_an_unknown_user(monkeypatch: pytest.MonkeyPatch) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    with pytest.raises(ValueError, match="no user found"):
        asyncio.run(
            grant_user_server_access(
                cast(SessionFactory, MagicMock()),
                user_email="missing@example.com",
                server_code="vps-1",
            )
        )


def test_seed_ss2022_creates_a_shadowsocks_profile_without_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    result = asyncio.run(seed_ss2022_protocol(cast(SessionFactory, MagicMock())))

    assert result.status is SeedProtocolStatus.CREATED
    protocol = cast(Protocol, session.add.call_args_list[0].args[0])
    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    assert protocol.code == "shadowsocks"
    assert protocol.engine == "xray"
    assert profile.code == "shadowsocks-2022"
    assert profile.transport == "raw"
    # Its own encryption; the vocabulary has no "none", so the column is NULL.
    assert profile.transport_security is None
    assert profile.required_port == 8451


def test_seed_ss2022_adblock_redirects_to_the_real_agent_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    asyncio.run(seed_ss2022_adblock_protocol(cast(SessionFactory, MagicMock())))

    profile = cast(ProtocolProfile, session.add.call_args_list[1].args[0])
    assert profile.code == "shadowsocks-2022-adblock"
    assert profile.ad_block is True
    assert profile.agent_profile_code == "shadowsocks-2022"


def test_seed_direct_protocols_adds_six_profiles_without_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=None)
    session.flush = _assign_ids_in_add_order(session)
    monkeypatch.setattr(topology_seed_module, "session_scope", fake_scope_for(session))

    results = asyncio.run(seed_direct_protocols(cast(SessionFactory, MagicMock())))

    assert [code for code, _ in results] == [
        "vless-enc",
        "vless-enc-adblock",
        "vmess-raw",
        "vmess-raw-adblock",
        "vmess-ws",
        "vmess-ws-adblock",
    ]
    profiles = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], ProtocolProfile)
    ]
    assert {p.transport_security for p in profiles} == {None}
    by_code = {p.code: p for p in profiles}
    assert by_code["vmess-ws"].transport == "websocket"
    assert by_code["vmess-ws"].required_port == 8455
    assert by_code["vless-enc-adblock"].agent_profile_code == "vless-enc"
    protocols = {
        call.args[0].code
        for call in session.add.call_args_list
        if isinstance(call.args[0], Protocol)
    }
    assert "vmess" in protocols
