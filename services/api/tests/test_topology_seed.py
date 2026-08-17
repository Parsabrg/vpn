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
    GrantAccessStatus,
    SeedProtocolStatus,
    create_vpn_server,
    grant_user_server_access,
    seed_wireguard_protocol,
)


def fake_scope_for(
    session: AsyncSession,
) -> Callable[[SessionFactory], AbstractAsyncContextManager[AsyncSession]]:
    @asynccontextmanager
    async def fake_scope(_factory: SessionFactory) -> AsyncIterator[AsyncSession]:
        yield session

    return fake_scope


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

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    # order: user, server, protocol, profile, existing-permission(None), existing-assignment(None)
    session.scalar = AsyncMock(side_effect=[user, server, protocol, profile, None, None])
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
    permission = cast(UserProtocolPermission, session.add.call_args_list[0].args[0])
    assignment = cast(UserServerAssignment, session.add.call_args_list[1].args[0])
    assert permission.state == CapabilityState.ENABLED.value
    assert assignment.state == LifecycleState.ACTIVE.value


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
    session.scalar = AsyncMock(
        side_effect=[user, server, protocol, profile, existing_permission, existing_assignment]
    )
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
