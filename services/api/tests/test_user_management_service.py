import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User, UserSession
from nebula_api.models.provisioning import (
    DeviceProtocolCredential,
    WireGuardPeer,
    XrayClient,
)
from nebula_api.models.types import (
    AccountState,
    DevicePlatform,
    LifecycleState,
    ProvisioningState,
)
from nebula_api.settings import Settings
from nebula_api.user_management.service import (
    UserManagementRejected,
    UserManagementService,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
DEVICE_ID = UUID("22222222-2222-4222-8222-222222222222")
SESSION_ID = UUID("33333333-3333-4333-8333-333333333333")
PASSWORD_HASH = "hash"  # noqa: S105 - test fixture


class ScalarRows:
    def __init__(self, values: Iterable[object]) -> None:
        self._values = list(values)

    def all(self) -> list[object]:
        return self._values


class ScriptedSession:
    def __init__(
        self,
        *,
        scalar_values: Iterable[object] = (),
        scalars_values: Iterable[Iterable[object]] = (),
    ) -> None:
        self.scalar_values = list(scalar_values)
        self.scalars_values = [list(values) for values in scalars_values]
        self.added: list[object] = []
        self.executed: list[object] = []
        self.commits = 0

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        return self.scalar_values.pop(0)

    async def scalars(self, _statement: object) -> ScalarRows:
        return ScalarRows(self.scalars_values.pop(0))

    async def execute(self, statement: object) -> object:
        self.executed.append(statement)
        return object()

    def add(self, value: object) -> None:
        self.added.append(value)

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


def service(
    factory: ScriptedFactory, *, redis: AllowingRedis | None = None
) -> UserManagementService:
    return UserManagementService(
        cast(SessionFactory, factory),
        cast(RedisAuthState, redis or AllowingRedis()),
        Settings(env="test"),
        clock=lambda: NOW,
    )


def active_user(**overrides: object) -> User:
    defaults: dict[str, object] = dict(
        id=USER_ID,
        email="user@example.com",
        email_normalized="user@example.com",
        username=None,
        username_normalized=None,
        password_hash=PASSWORD_HASH,
        state=AccountState.ACTIVE,
        device_limit=3,
        activated_at=NOW - timedelta(days=1),
        created_at=NOW - timedelta(days=1),
    )
    defaults.update(overrides)
    return User(**defaults)


def active_device(**overrides: object) -> Device:
    defaults: dict[str, object] = dict(
        id=DEVICE_ID,
        user_id=USER_ID,
        name="Laptop",
        platform=DevicePlatform.WINDOWS,
        client_version="1.0.0",
        state=LifecycleState.ACTIVE,
        created_at=NOW,
    )
    defaults.update(overrides)
    return Device(**defaults)


def active_session(**overrides: object) -> UserSession:
    defaults: dict[str, object] = dict(
        id=SESSION_ID,
        user_id=USER_ID,
        device_id=DEVICE_ID,
        family_id=uuid4(),
        state=LifecycleState.ACTIVE,
        expires_at=NOW + timedelta(days=30),
        created_at=NOW,
    )
    defaults.update(overrides)
    return UserSession(**defaults)


def test_list_users_returns_page() -> None:
    row = active_user()
    session = ScriptedSession(scalar_values=[1], scalars_values=[[row]])
    instance = service(ScriptedFactory(session))

    page = asyncio.run(
        instance.list_users(state=None, email_prefix=None, username_prefix=None, limit=50, offset=0)
    )

    assert page.total == 1
    assert page.items[0].id == USER_ID


def test_get_user_detail_returns_none_when_missing() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    detail = asyncio.run(instance.get_user_detail(USER_ID))

    assert detail is None


def test_get_user_detail_returns_devices_and_sessions() -> None:
    session = ScriptedSession(
        scalar_values=[active_user()],
        scalars_values=[[active_device()], [active_session()]],
    )
    instance = service(ScriptedFactory(session))

    detail = asyncio.run(instance.get_user_detail(USER_ID))

    assert detail is not None
    assert detail.devices[0].id == DEVICE_ID
    assert detail.sessions[0].id == SESSION_ID


def test_disable_user_transitions_active_to_disabled() -> None:
    user = active_user()
    # Three scalars(): the session sweep, then the user's devices (none here),
    # which is where the credential cascade would start.
    session = ScriptedSession(scalar_values=[user], scalars_values=[[], []])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.disable_user(
            user_id=USER_ID, admin_id=ADMIN_ID, network_prefix="203.0.113.0/24", request_id=uuid4()
        )
    )

    assert summary.state is AccountState.DISABLED
    assert user.disabled_at == NOW
    assert any(type(item).__name__ == "AuditLog" for item in session.added)


def test_disable_user_is_idempotent() -> None:
    user = active_user(state=AccountState.DISABLED, disabled_at=NOW)
    session = ScriptedSession(scalar_values=[user])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.disable_user(
            user_id=USER_ID, admin_id=ADMIN_ID, network_prefix="203.0.113.0/24", request_id=uuid4()
        )
    )

    assert summary.state is AccountState.DISABLED
    assert session.added == []


def test_disable_user_rejects_pending_activation() -> None:
    user = active_user(state=AccountState.PENDING_ACTIVATION, activated_at=None)
    session = ScriptedSession(scalar_values=[user])
    instance = service(ScriptedFactory(session))

    with pytest.raises(UserManagementRejected):
        asyncio.run(
            instance.disable_user(
                user_id=USER_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_disable_user_rejects_unknown_user() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(UserManagementRejected):
        asyncio.run(
            instance.disable_user(
                user_id=USER_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_reactivate_user_transitions_disabled_to_active() -> None:
    user = active_user(state=AccountState.DISABLED, disabled_at=NOW)
    session = ScriptedSession(scalar_values=[user])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.reactivate_user(
            user_id=USER_ID, admin_id=ADMIN_ID, network_prefix="203.0.113.0/24", request_id=uuid4()
        )
    )

    assert summary.state is AccountState.ACTIVE
    assert user.disabled_at is None


def test_reactivate_user_is_idempotent() -> None:
    user = active_user(state=AccountState.ACTIVE)
    session = ScriptedSession(scalar_values=[user])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.reactivate_user(
            user_id=USER_ID, admin_id=ADMIN_ID, network_prefix="203.0.113.0/24", request_id=uuid4()
        )
    )

    assert summary.state is AccountState.ACTIVE


def test_reactivate_user_rejects_non_disabled_state() -> None:
    user = active_user(state=AccountState.SUSPENDED)
    session = ScriptedSession(scalar_values=[user])
    instance = service(ScriptedFactory(session))

    with pytest.raises(UserManagementRejected):
        asyncio.run(
            instance.reactivate_user(
                user_id=USER_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_revoke_device_transitions_active_to_revoked() -> None:
    device = active_device()
    # The session sweep, then the cascade's peer and client lookups.
    session = ScriptedSession(scalar_values=[device], scalars_values=[[], [], []])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_device(
            user_id=USER_ID,
            device_id=DEVICE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state is LifecycleState.REVOKED
    assert device.revoked_at == NOW


def test_revoke_device_is_idempotent() -> None:
    device = active_device(state=LifecycleState.REVOKED, revoked_at=NOW)
    session = ScriptedSession(scalar_values=[device])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_device(
            user_id=USER_ID,
            device_id=DEVICE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state is LifecycleState.REVOKED


def test_revoke_device_rejects_unknown_device() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(UserManagementRejected):
        asyncio.run(
            instance.revoke_device(
                user_id=USER_ID,
                device_id=DEVICE_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_revoke_session_transitions_active_to_revoked() -> None:
    user_session = active_session()
    session = ScriptedSession(scalar_values=[user_session])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_session(
            user_id=USER_ID,
            session_id=SESSION_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state is LifecycleState.REVOKED
    assert user_session.revoked_at == NOW


def test_revoke_session_is_idempotent() -> None:
    user_session = active_session(state=LifecycleState.REVOKED, revoked_at=NOW)
    session = ScriptedSession(scalar_values=[user_session])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_session(
            user_id=USER_ID,
            session_id=SESSION_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state is LifecycleState.REVOKED


def test_revoke_session_rejects_unknown_session() -> None:
    session = ScriptedSession(scalar_values=[None])
    instance = service(ScriptedFactory(session))

    with pytest.raises(UserManagementRejected):
        asyncio.run(
            instance.revoke_session(
                user_id=USER_ID,
                session_id=SESSION_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


# --- Revocation cascades to VPN credentials --------------------------------
#
# Revoking a device used to stop at the database row and the API session: the
# WireGuard peer and Xray client stayed in the server's configuration and kept
# authenticating. The admin UI showed the device as revoked while the device
# still held a working tunnel, indefinitely and silently. These fix that
# behaviour in place, so it cannot regress unnoticed.


def live_peer(**overrides: object) -> WireGuardPeer:
    defaults: dict[str, object] = dict(
        id=uuid4(),
        device_id=DEVICE_ID,
        credential_id=uuid4(),
        vpn_server_id=uuid4(),
        state=ProvisioningState.ACTIVE.value,
    )
    defaults.update(overrides)
    return WireGuardPeer(**defaults)


def live_client(**overrides: object) -> XrayClient:
    defaults: dict[str, object] = dict(
        id=uuid4(),
        device_id=DEVICE_ID,
        credential_id=uuid4(),
        vpn_server_id=uuid4(),
        state=ProvisioningState.ACTIVE.value,
    )
    defaults.update(overrides)
    return XrayClient(**defaults)


def credential(row_id: UUID) -> DeviceProtocolCredential:
    return DeviceProtocolCredential(id=row_id, state=ProvisioningState.ACTIVE.value)


def test_revoke_device_marks_its_xray_client_revoking() -> None:
    device = active_device()
    client = live_client()
    session = ScriptedSession(
        scalar_values=[device, credential(client.credential_id)],
        scalars_values=[[], [], [client]],
    )
    instance = service(ScriptedFactory(session))

    asyncio.run(
        instance.revoke_device(
            user_id=USER_ID,
            device_id=DEVICE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert client.state == ProvisioningState.REVOKING.value


def test_revoke_device_marks_its_wireguard_peer_revoking() -> None:
    device = active_device()
    peer = live_peer()
    session = ScriptedSession(
        scalar_values=[device, credential(peer.credential_id)],
        scalars_values=[[], [peer], []],
    )
    instance = service(ScriptedFactory(session))

    asyncio.run(
        instance.revoke_device(
            user_id=USER_ID,
            device_id=DEVICE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert peer.state == ProvisioningState.REVOKING.value


def test_revoke_device_carries_the_credential_row_with_it() -> None:
    """The credential row is what the app reads back, so leaving it ACTIVE
    would show a revoked device a live credential."""

    device = active_device()
    client = live_client()
    credential_row = credential(client.credential_id)
    session = ScriptedSession(
        scalar_values=[device, credential_row], scalars_values=[[], [], [client]]
    )
    instance = service(ScriptedFactory(session))

    asyncio.run(
        instance.revoke_device(
            user_id=USER_ID,
            device_id=DEVICE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert credential_row.state == ProvisioningState.REVOKING.value


def test_revoke_device_without_credentials_still_succeeds() -> None:
    """A device that never provisioned anything must revoke cleanly rather
    than fail looking for credentials it does not have."""

    device = active_device()
    session = ScriptedSession(scalar_values=[device], scalars_values=[[], [], []])
    instance = service(ScriptedFactory(session))

    summary = asyncio.run(
        instance.revoke_device(
            user_id=USER_ID,
            device_id=DEVICE_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert summary.state is LifecycleState.REVOKED
    assert session.commits == 1


def test_disable_user_cascades_to_every_device() -> None:
    """Not just the first: a user with several devices keeps a working tunnel
    on any device the cascade skips."""

    user = active_user()
    second_device_id = uuid4()
    first = live_client()
    second = live_client(device_id=second_device_id)
    session = ScriptedSession(
        scalar_values=[
            user,
            credential(first.credential_id),
            credential(second.credential_id),
        ],
        scalars_values=[
            [],  # session sweep
            [DEVICE_ID, second_device_id],  # the user's devices
            [],  # device 1 peers
            [first],  # device 1 clients
            [],  # device 2 peers
            [second],  # device 2 clients
        ],
    )
    instance = service(ScriptedFactory(session))

    asyncio.run(
        instance.disable_user(
            user_id=USER_ID, admin_id=ADMIN_ID, network_prefix="203.0.113.0/24", request_id=uuid4()
        )
    )

    assert first.state == ProvisioningState.REVOKING.value
    assert second.state == ProvisioningState.REVOKING.value


def test_disable_user_leaves_the_devices_active() -> None:
    """Disabling is reversible through reactivate_user; revoking the devices
    would not be. Only the credentials go."""

    user = active_user()
    client = live_client()
    session = ScriptedSession(
        scalar_values=[user, credential(client.credential_id)],
        scalars_values=[[], [DEVICE_ID], [], [client]],
    )
    device = active_device()
    instance = service(ScriptedFactory(session))

    asyncio.run(
        instance.disable_user(
            user_id=USER_ID, admin_id=ADMIN_ID, network_prefix="203.0.113.0/24", request_id=uuid4()
        )
    )

    assert device.state is LifecycleState.ACTIVE
    assert client.state == ProvisioningState.REVOKING.value


def test_set_device_limit_changes_it_and_audits() -> None:
    user = active_user()
    session = ScriptedSession(scalar_values=[user])

    limit = asyncio.run(
        service(ScriptedFactory(session)).set_device_limit(
            user_id=USER_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            device_limit=7,
        )
    )

    assert limit == 7
    assert user.device_limit == 7
    assert any(getattr(item, "reason_code", None) == "device_limit_set" for item in session.added)


def _set_expiry(session: ScriptedSession, expires_at: datetime | None) -> None:
    asyncio.run(
        service(ScriptedFactory(session)).set_expiry(
            user_id=USER_ID,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            expires_at=expires_at,
        )
    )


def test_set_expiry_sets_and_clears_it() -> None:
    user = active_user()
    when = NOW + timedelta(days=30)

    session = ScriptedSession(scalar_values=[user])
    _set_expiry(session, when)
    assert user.expires_at == when
    assert any(getattr(item, "reason_code", None) == "expiry_set" for item in session.added)

    _set_expiry(ScriptedSession(scalar_values=[user]), None)
    assert user.expires_at is None


def test_set_expiry_rejects_an_unknown_user() -> None:
    with pytest.raises(UserManagementRejected):
        _set_expiry(ScriptedSession(scalar_values=[None]), None)


def test_set_device_limit_rejects_an_unknown_user() -> None:
    with pytest.raises(UserManagementRejected):
        asyncio.run(
            service(ScriptedFactory(ScriptedSession(scalar_values=[None]))).set_device_limit(
                user_id=USER_ID,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
                device_limit=2,
            )
        )
