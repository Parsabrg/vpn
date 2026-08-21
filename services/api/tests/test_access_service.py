import asyncio
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from nebula_api.access.service import (
    AccessRejected,
    AccessService,
    PermissionListEntry,
    PermissionPage,
)
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.models.topology import (
    ProtocolProfile,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)
from nebula_api.models.types import CapabilityState, LifecycleState
from nebula_api.settings import Settings

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
PROFILE_ID = UUID("22222222-2222-4222-8222-222222222222")
SERVER_ID = UUID("33333333-3333-4333-8333-333333333333")
PERMISSION_ID = UUID("44444444-4444-4444-8444-444444444444")
ASSIGNMENT_ID = UUID("55555555-5555-4555-8555-555555555555")


class MappingRows:
    def __init__(self, rows: Iterable[Mapping[str, object]]) -> None:
        self._rows = list(rows)

    def mappings(self) -> "MappingRows":
        return self

    def all(self) -> list[Mapping[str, object]]:
        return self._rows


class ScriptedSession:
    def __init__(
        self,
        *,
        scalar_values: Iterable[object] = (),
        execute_rows: Iterable[Iterable[Mapping[str, object]]] = (),
    ) -> None:
        self.scalar_values = list(scalar_values)
        self.execute_rows = [list(rows) for rows in execute_rows]
        self.added: list[object] = []
        self.executed: list[object] = []
        self.commits = 0

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        return self.scalar_values.pop(0)

    async def execute(self, statement: object, params: object = None) -> object:
        self.executed.append((statement, params))
        if self.execute_rows:
            return MappingRows(self.execute_rows.pop(0))
        return MappingRows([])

    def add(self, value: object) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        return self.sessions.pop(0)


class AllowingRedis:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed

    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        assert limit > 0 and window_seconds > 0
        return self.allowed


def service(factory: ScriptedFactory, *, redis: AllowingRedis | None = None) -> AccessService:
    return AccessService(
        cast(SessionFactory, factory),
        cast(RedisAuthState, redis or AllowingRedis()),
        Settings(env="test"),
        clock=lambda: NOW,
    )


def protocol_profile(**overrides: object) -> ProtocolProfile:
    defaults: dict[str, object] = dict(
        id=PROFILE_ID,
        protocol_id=uuid4(),
        code="wireguard-native",
        version=1,
        display_name="WireGuard",
        state="implemented",
        requires_udp=True,
        is_full_tunnel=True,
        created_at=NOW,
    )
    defaults.update(overrides)
    return ProtocolProfile(**defaults)


def vpn_server(**overrides: object) -> VPNServer:
    defaults: dict[str, object] = dict(
        id=SERVER_ID,
        code="fra-1",
        display_name="Frankfurt 1",
        state="active",
        agent_host="10.0.0.1",
        agent_port=9443,
        public_host="fra-1.example.test",
        maximum_devices=1000,
        created_at=NOW,
    )
    defaults.update(overrides)
    return VPNServer(**defaults)


def existing_permission(**overrides: object) -> UserProtocolPermission:
    defaults: dict[str, object] = dict(
        id=PERMISSION_ID,
        user_id=USER_ID,
        protocol_profile_id=PROFILE_ID,
        granted_by_admin_id=None,
        state=CapabilityState.ENABLED.value,
        granted_at=NOW - timedelta(days=1),
        created_at=NOW - timedelta(days=1),
    )
    defaults.update(overrides)
    return UserProtocolPermission(**defaults)


def existing_assignment(**overrides: object) -> UserServerAssignment:
    defaults: dict[str, object] = dict(
        id=ASSIGNMENT_ID,
        user_id=USER_ID,
        vpn_server_id=SERVER_ID,
        assigned_by_admin_id=None,
        state=LifecycleState.ACTIVE.value,
        assigned_at=NOW - timedelta(days=1),
        created_at=NOW - timedelta(days=1),
    )
    defaults.update(overrides)
    return UserServerAssignment(**defaults)


def test_list_user_permissions_returns_empty_when_none() -> None:
    session = ScriptedSession(execute_rows=[[]])
    instance = service(ScriptedFactory(session))

    items = asyncio.run(instance.list_user_permissions(USER_ID))

    assert items == []


def test_list_user_permissions_maps_rows() -> None:
    row = {
        "id": PERMISSION_ID,
        "protocol_profile_id": PROFILE_ID,
        "profile_code": "wireguard-native",
        "profile_display_name": "WireGuard",
        "state": "enabled",
        "granted_by_admin_id": ADMIN_ID,
        "granted_at": NOW,
        "expires_at": None,
        "revoked_at": None,
    }
    session = ScriptedSession(execute_rows=[[row]])
    instance = service(ScriptedFactory(session))

    items = asyncio.run(instance.list_user_permissions(USER_ID))

    assert items[0].id == PERMISSION_ID
    assert items[0].state == "enabled"


def test_list_user_assignments_maps_rows() -> None:
    row = {
        "id": ASSIGNMENT_ID,
        "vpn_server_id": SERVER_ID,
        "server_code": "fra-1",
        "server_display_name": "Frankfurt 1",
        "state": "active",
        "assigned_by_admin_id": ADMIN_ID,
        "assigned_at": NOW,
        "expires_at": None,
        "revoked_at": None,
    }
    session = ScriptedSession(execute_rows=[[row]])
    instance = service(ScriptedFactory(session))

    items = asyncio.run(instance.list_user_assignments(USER_ID))

    assert items[0].id == ASSIGNMENT_ID
    assert items[0].state == "active"


def test_list_all_permissions_returns_page() -> None:
    row = {
        "id": PERMISSION_ID,
        "user_id": USER_ID,
        "user_email": "user@example.com",
        "protocol_profile_id": PROFILE_ID,
        "profile_code": "wireguard-native",
        "profile_display_name": "WireGuard",
        "state": "enabled",
        "granted_by_admin_id": ADMIN_ID,
        "granted_at": NOW,
        "expires_at": None,
        "revoked_at": None,
    }
    session = ScriptedSession(execute_rows=[[row]], scalar_values=[1])
    instance = service(ScriptedFactory(session))

    page = asyncio.run(instance.list_all_permissions(state=None, limit=50, offset=0))

    assert isinstance(page, PermissionPage)
    assert page.total == 1
    assert isinstance(page.items[0], PermissionListEntry)
    assert page.items[0].user_email == "user@example.com"


def test_list_all_assignments_returns_page() -> None:
    row = {
        "id": ASSIGNMENT_ID,
        "user_id": USER_ID,
        "user_email": "user@example.com",
        "vpn_server_id": SERVER_ID,
        "server_code": "fra-1",
        "server_display_name": "Frankfurt 1",
        "state": "active",
        "assigned_by_admin_id": ADMIN_ID,
        "assigned_at": NOW,
        "expires_at": None,
        "revoked_at": None,
    }
    session = ScriptedSession(execute_rows=[[row]], scalar_values=[1])
    instance = service(ScriptedFactory(session))

    page = asyncio.run(instance.list_all_assignments(state=None, limit=50, offset=0))

    assert page.total == 1
    assert page.items[0].server_code == "fra-1"


def test_list_all_permissions_filters_by_state() -> None:
    session = ScriptedSession(execute_rows=[[]], scalar_values=[0])
    instance = service(ScriptedFactory(session))

    page = asyncio.run(instance.list_all_permissions(state="enabled", limit=50, offset=0))

    assert page.total == 0


def test_list_all_assignments_filters_by_state() -> None:
    session = ScriptedSession(execute_rows=[[]], scalar_values=[0])
    instance = service(ScriptedFactory(session))

    page = asyncio.run(instance.list_all_assignments(state="active", limit=50, offset=0))

    assert page.total == 0


def test_grant_permission_creates_new_row() -> None:
    profile = protocol_profile()
    session = ScriptedSession(scalar_values=[profile, None])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.grant_permission(
            user_id=USER_ID,
            protocol_profile_id=PROFILE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == CapabilityState.ENABLED.value
    assert any(type(item).__name__ == "UserProtocolPermission" for item in session.added)
    assert any(type(item).__name__ == "AuditLog" for item in session.added)


def test_grant_permission_reactivates_disabled_row() -> None:
    profile = protocol_profile()
    permission = existing_permission(state=CapabilityState.DISABLED.value, revoked_at=NOW)
    session = ScriptedSession(scalar_values=[profile, permission])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.grant_permission(
            user_id=USER_ID,
            protocol_profile_id=PROFILE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == CapabilityState.ENABLED.value
    assert permission.revoked_at is None
    assert any(type(item).__name__ == "AuditLog" for item in session.added)


def test_grant_permission_is_idempotent() -> None:
    profile = protocol_profile()
    permission = existing_permission(state=CapabilityState.ENABLED.value)
    session = ScriptedSession(scalar_values=[profile, permission])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.grant_permission(
            user_id=USER_ID,
            protocol_profile_id=PROFILE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == CapabilityState.ENABLED.value
    assert session.added == []


def test_grant_permission_rejects_unknown_profile() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(AccessRejected):
        asyncio.run(
            instance.grant_permission(
                user_id=USER_ID,
                protocol_profile_id=PROFILE_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_revoke_permission_transitions_enabled_to_disabled() -> None:
    permission = existing_permission(state=CapabilityState.ENABLED.value)
    profile = protocol_profile()
    session = ScriptedSession(scalar_values=[permission, profile])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_permission(
            user_id=USER_ID,
            protocol_profile_id=PROFILE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == CapabilityState.DISABLED.value
    assert permission.revoked_at == NOW


def test_revoke_permission_is_idempotent() -> None:
    permission = existing_permission(state=CapabilityState.DISABLED.value, revoked_at=NOW)
    profile = protocol_profile()
    session = ScriptedSession(scalar_values=[permission, profile])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_permission(
            user_id=USER_ID,
            protocol_profile_id=PROFILE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == CapabilityState.DISABLED.value
    assert session.added == []


def test_revoke_permission_rejects_when_profile_missing() -> None:
    permission = existing_permission(state=CapabilityState.ENABLED.value)
    session = ScriptedSession(scalar_values=[permission, None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(AccessRejected):
        asyncio.run(
            instance.revoke_permission(
                user_id=USER_ID,
                protocol_profile_id=PROFILE_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_revoke_permission_rejects_missing_row() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(AccessRejected):
        asyncio.run(
            instance.revoke_permission(
                user_id=USER_ID,
                protocol_profile_id=PROFILE_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_assign_server_creates_new_row() -> None:
    server = vpn_server()
    session = ScriptedSession(scalar_values=[server, None])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.assign_server(
            user_id=USER_ID,
            vpn_server_id=SERVER_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == LifecycleState.ACTIVE.value
    assert any(type(item).__name__ == "UserServerAssignment" for item in session.added)


def test_assign_server_reactivates_revoked_row() -> None:
    server = vpn_server()
    assignment = existing_assignment(state=LifecycleState.REVOKED.value, revoked_at=NOW)
    session = ScriptedSession(scalar_values=[server, assignment])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.assign_server(
            user_id=USER_ID,
            vpn_server_id=SERVER_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == LifecycleState.ACTIVE.value
    assert assignment.revoked_at is None


def test_assign_server_is_idempotent() -> None:
    server = vpn_server()
    assignment = existing_assignment(state=LifecycleState.ACTIVE.value)
    session = ScriptedSession(scalar_values=[server, assignment])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.assign_server(
            user_id=USER_ID,
            vpn_server_id=SERVER_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == LifecycleState.ACTIVE.value
    assert session.added == []


def test_assign_server_rejects_unknown_server() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(AccessRejected):
        asyncio.run(
            instance.assign_server(
                user_id=USER_ID,
                vpn_server_id=SERVER_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_revoke_assignment_transitions_active_to_revoked() -> None:
    assignment = existing_assignment(state=LifecycleState.ACTIVE.value)
    server = vpn_server()
    session = ScriptedSession(scalar_values=[assignment, server])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_assignment(
            user_id=USER_ID,
            vpn_server_id=SERVER_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == LifecycleState.REVOKED.value
    assert assignment.revoked_at == NOW


def test_revoke_assignment_rejects_when_server_missing() -> None:
    assignment = existing_assignment(state=LifecycleState.ACTIVE.value)
    session = ScriptedSession(scalar_values=[assignment, None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(AccessRejected):
        asyncio.run(
            instance.revoke_assignment(
                user_id=USER_ID,
                vpn_server_id=SERVER_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_revoke_assignment_is_idempotent() -> None:
    assignment = existing_assignment(state=LifecycleState.REVOKED.value, revoked_at=NOW)
    server = vpn_server()
    session = ScriptedSession(scalar_values=[assignment, server])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_assignment(
            user_id=USER_ID,
            vpn_server_id=SERVER_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state == LifecycleState.REVOKED.value
    assert session.added == []


def test_revoke_assignment_rejects_missing_row() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(AccessRejected):
        asyncio.run(
            instance.revoke_assignment(
                user_id=USER_ID,
                vpn_server_id=SERVER_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_naive_clock_is_rejected() -> None:
    instance = AccessService(
        cast(SessionFactory, ScriptedFactory(ScriptedSession())),
        cast(RedisAuthState, AllowingRedis()),
        Settings(env="test"),
        clock=lambda: datetime(2026, 7, 20, 12, 0),
    )

    with pytest.raises(ValueError, match="timezone aware"):
        asyncio.run(
            instance.grant_permission(
                user_id=USER_ID,
                protocol_profile_id=PROFILE_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_mutations_are_rate_limited() -> None:
    session = ScriptedSession()
    instance = service(ScriptedFactory(session), redis=AllowingRedis(allowed=False))

    with pytest.raises(AccessRejected):
        asyncio.run(
            instance.grant_permission(
                user_id=USER_ID,
                protocol_profile_id=PROFILE_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert session.commits == 1
