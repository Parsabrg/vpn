import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nebula_api.auth.device_identity import hash_hardware_id
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.auth.user_service import (
    AccountExpired,
    AuthenticatedUser,
    AuthenticationRateLimited,
    AuthenticationRejected,
    DeviceLimitReached,
    UserAuthService,
)
from nebula_api.db.engine import SessionFactory
from nebula_api.models.approval import PasswordResetToken
from nebula_api.models.identity import Device, RefreshToken, User, UserSession
from nebula_api.models.operations import AuditLog, EmailDelivery
from nebula_api.models.types import AccountState, DevicePlatform, LifecycleState, TokenState
from nebula_api.passwords import hash_password
from nebula_api.settings import Settings

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
USER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
DEVICE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
SESSION_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
PASSWORD = "correct-password-canary"  # noqa: S105 - test fixture


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
        self.flushes = 0

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        if not self.scalar_values:
            raise AssertionError("unexpected scalar query")
        return self.scalar_values.pop(0)

    async def scalars(self, _statement: object) -> ScalarRows:
        if not self.scalars_values:
            raise AssertionError("unexpected scalars query")
        return ScalarRows(self.scalars_values.pop(0))

    async def execute(self, statement: object) -> object:
        self.executed.append(statement)
        return object()

    def add(self, value: object) -> None:
        self.added.append(value)

    def add_all(self, values: Iterable[object]) -> None:
        self.added.extend(values)

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.commits += 1


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        if not self.sessions:
            raise AssertionError("unexpected database session")
        return self.sessions.pop(0)


class AllowingRedis:
    def __init__(self) -> None:
        self.allowed = True
        self.buckets: list[tuple[RateBucket, ...]] = []
        self.limits: list[int] = []

    async def rate_limit(
        self,
        buckets: tuple[RateBucket, ...],
        *,
        limit: int,
        window_seconds: int,
    ) -> bool:
        assert limit > 0 and window_seconds > 0
        self.buckets.append(buckets)
        self.limits.append(limit)
        return self.allowed


def keys() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(
        private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32}, {1: b"x" * 32}
    )


def user() -> User:
    return User(
        id=USER_ID,
        email="user@example.com",
        email_normalized="user@example.com",
        username="user",
        username_normalized="user",
        password_hash=hash_password(PASSWORD),
        state=AccountState.ACTIVE,
        device_limit=3,
        activated_at=NOW - timedelta(days=1),
    )


def device() -> Device:
    return Device(
        id=DEVICE_ID,
        user_id=USER_ID,
        name="Laptop",
        platform=DevicePlatform.WINDOWS,
        client_version="1.0.0",
        state=LifecycleState.ACTIVE,
    )


def active_session() -> UserSession:
    return UserSession(
        id=SESSION_ID,
        user_id=USER_ID,
        device_id=DEVICE_ID,
        family_id=uuid4(),
        state=LifecycleState.ACTIVE,
        expires_at=NOW + timedelta(days=30),
    )


def refresh_record(*, state: TokenState = TokenState.ACTIVE) -> RefreshToken:
    return RefreshToken(
        id=uuid4(),
        session_id=SESSION_ID,
        token_digest=b"d" * 32,
        key_version=1,
        state=state,
        expires_at=NOW + timedelta(days=30),
        consumed_at=NOW if state is TokenState.CONSUMED else None,
        replaced_by_id=uuid4() if state is TokenState.CONSUMED else None,
    )


def service(
    factory: ScriptedFactory, redis: AllowingRedis | None = None
) -> tuple[UserAuthService, AllowingRedis]:
    effective_redis = redis or AllowingRedis()
    instance = UserAuthService(
        cast(SessionFactory, factory),
        cast(RedisAuthState, effective_redis),
        keys(),
        Settings(env="test"),
        clock=lambda: NOW,
    )
    return instance, effective_redis


def test_login_existing_device_issues_fresh_family_and_audits() -> None:
    database = ScriptedSession(scalar_values=(user(), device()), scalars_values=((),))
    auth, redis = service(ScriptedFactory(database))

    pair = asyncio.run(
        auth.login(
            identifier="USER@example.com",
            password=PASSWORD,
            device_id=DEVICE_ID,
            device_name="Renamed laptop",
            platform=DevicePlatform.WINDOWS,
            client_version="2.0.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert pair.access_token.count(".") == 2
    assert pair.refresh_token.startswith("v1.")
    assert pair.refresh_token not in repr(pair)
    assert any(isinstance(item, UserSession) for item in database.added)
    assert any(isinstance(item, RefreshToken) for item in database.added)
    assert any(isinstance(item, AuditLog) for item in database.added)
    assert database.commits == 1
    assert all("USER@example.com" not in bucket.subject for bucket in redis.buckets[0])


def test_login_unknown_user_performs_generic_denial_and_audit() -> None:
    database = ScriptedSession(scalar_values=(None,))
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.login(
                identifier="missing@example.com",
                password="wrong-password-canary",  # noqa: S106 - test fixture
                device_id=None,
                device_name="Phone",
                platform=DevicePlatform.ANDROID,
                client_version="1.0.0",
                network_prefix="198.51.100.0/24",
                request_id=uuid4(),
            )
        )

    assert database.commits == 1
    assert any(isinstance(item, AuditLog) for item in database.added)


def test_login_registers_new_device_with_quota_lock() -> None:
    database = ScriptedSession(scalar_values=(user(), 1), scalars_values=((),))
    auth, _redis = service(ScriptedFactory(database))

    asyncio.run(
        auth.login(
            identifier="user",
            password=PASSWORD,
            device_id=None,
            device_name="Android",
            platform=DevicePlatform.ANDROID,
            client_version="1.0.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert any(isinstance(item, Device) for item in database.added)


def _login_with_device(auth: UserAuthService, device_id: UUID | None) -> None:
    asyncio.run(
        auth.login(
            identifier="user@example.com",
            password=PASSWORD,
            device_id=device_id,
            device_name="Phone",
            platform=DevicePlatform.ANDROID,
            client_version="1.0.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )


def test_a_device_id_from_another_account_registers_a_new_device() -> None:
    # A phone keeps the device id it was given and sends it on every sign-in,
    # including after signing out and in as somebody else. The lookup is
    # scoped to this account, so that id finds nothing -- which used to be a
    # refusal indistinguishable from a wrong password, forever, on that phone.
    foreign = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    database = ScriptedSession(scalar_values=(user(), None, 0), scalars_values=((),))
    auth, _redis = service(ScriptedFactory(database))

    _login_with_device(auth, foreign)

    registered = [item for item in database.added if isinstance(item, Device)]
    assert len(registered) == 1
    assert registered[0].user_id == USER_ID
    # A fresh device, never the id the client sent: that one belongs to
    # somebody else and must not be adopted.
    assert registered[0].id != foreign
    assert any(isinstance(item, UserSession) for item in database.added)


def test_a_revoked_device_of_this_account_registers_a_new_device() -> None:
    # Revoking a device ends its sessions and credentials; it is not a ban on
    # the person, who already proved the password and could sign in with no
    # id at all. Refusing only strands the install that was revoked.
    revoked = device()
    revoked.state = LifecycleState.REVOKED
    database = ScriptedSession(scalar_values=(user(), revoked, 0), scalars_values=((),))
    auth, _redis = service(ScriptedFactory(database))

    _login_with_device(auth, DEVICE_ID)

    registered = [item for item in database.added if isinstance(item, Device)]
    assert len(registered) == 1
    assert registered[0].id != DEVICE_ID
    assert revoked.state is LifecycleState.REVOKED


def _reinstalled_device(hardware_id: str) -> Device:
    # The device the account already has for this hardware, as it sits in the
    # database: active, with the stored HMAC of its hardware id.
    version, digest = hash_hardware_id(hardware_id, {1: b"p" * 32}, key_version=1)
    existing = device()
    existing.hardware_key_version = version
    existing.hardware_hash = digest
    return existing


def test_a_reinstall_reuses_the_device_for_its_hardware() -> None:
    # Uninstalling wiped the stored device id, so the reinstalled app sends
    # none -- but the same hardware id. That must reuse the one row, not add
    # a second for one phone, and not spend a device-limit slot.
    existing = _reinstalled_device("stable-hardware-xyz")
    database = ScriptedSession(scalar_values=(user(),), scalars_values=((existing,), ()))
    auth, _redis = service(ScriptedFactory(database))

    asyncio.run(
        auth.login(
            identifier="user@example.com",
            password=PASSWORD,
            device_id=None,
            device_name="Phone again",
            platform=DevicePlatform.ANDROID,
            client_version="1.2.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            hardware_id="stable-hardware-xyz",
        )
    )

    assert not any(isinstance(item, Device) for item in database.added)
    # The session binds to the device that already existed.
    assert existing.name == "Phone again"
    assert any(
        isinstance(item, UserSession) and item.device_id == existing.id for item in database.added
    )


def test_a_different_hardware_registers_a_new_device() -> None:
    # A genuinely new phone: no stored device matches its hardware, so it
    # registers, subject to the limit (the count scalar follows the empty
    # hardware lookup).
    existing = _reinstalled_device("the-old-phone")
    database = ScriptedSession(scalar_values=(user(), 1), scalars_values=((existing,), ()))
    auth, _redis = service(ScriptedFactory(database))

    asyncio.run(
        auth.login(
            identifier="user@example.com",
            password=PASSWORD,
            device_id=None,
            device_name="A new phone",
            platform=DevicePlatform.ANDROID,
            client_version="1.2.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            hardware_id="a-brand-new-phone",
        )
    )

    registered = [item for item in database.added if isinstance(item, Device)]
    assert len(registered) == 1
    assert registered[0].hardware_hash is not None


def test_a_reinstall_at_the_device_limit_still_connects() -> None:
    # The account is at its limit, but the reinstall reuses its own existing
    # slot, so it must not be refused -- the bug was that it counted as a new
    # device and hit the limit.
    existing = _reinstalled_device("my-hardware")
    user_at_limit = user()
    user_at_limit.device_limit = 1
    database = ScriptedSession(scalar_values=(user_at_limit,), scalars_values=((existing,), ()))
    auth, _redis = service(ScriptedFactory(database))

    asyncio.run(
        auth.login(
            identifier="user@example.com",
            password=PASSWORD,
            device_id=None,
            device_name="Phone",
            platform=DevicePlatform.ANDROID,
            client_version="1.0.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            hardware_id="my-hardware",
        )
    )

    assert not any(isinstance(item, Device) for item in database.added)


def test_an_unusable_device_id_still_counts_against_the_device_limit() -> None:
    # Falling through to registration must not become a way around the limit.
    foreign = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    database = ScriptedSession(scalar_values=(user(), None, 3))
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(DeviceLimitReached):
        _login_with_device(auth, foreign)

    assert not any(isinstance(item, Device) for item in database.added)


def test_reaching_the_device_limit_is_audited_against_the_account() -> None:
    # The password was right, so this denial is the account's and says why.
    # Without a row it looks exactly like a mistyped password.
    database = ScriptedSession(scalar_values=(user(), 3))
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected):
        _login_with_device(auth, None)

    entry = next(item for item in database.added if isinstance(item, AuditLog))
    assert entry.actor_kind == "user"
    assert entry.actor_id == USER_ID
    assert entry.outcome == "denied"
    assert entry.reason_code == "device_limit_reached"
    assert database.commits == 1


def test_refresh_rotates_once_with_deferred_successor_and_new_access_token() -> None:
    token = refresh_record()
    session = active_session()
    database = ScriptedSession(scalar_values=(token, session, user(), device()))
    auth, _redis = service(ScriptedFactory(database))
    raw = "v1." + "A" * 43
    token.token_digest = (
        __import__("nebula_api.auth.opaque_tokens", fromlist=["digest_opaque_token"])
        .digest_opaque_token(raw, {1: b"p" * 32}, namespace="refresh")
        .value
    )

    pair = asyncio.run(
        auth.refresh(
            refresh_token=raw,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert token.state is TokenState.CONSUMED
    assert token.replaced_by_id is not None
    assert database.flushes == 1 and database.commits == 1
    assert pair.refresh_token != raw


def test_refresh_reuse_revokes_family_and_records_detection() -> None:
    token = refresh_record(state=TokenState.CONSUMED)
    session = active_session()
    database = ScriptedSession(scalar_values=(token, session))
    auth, _redis = service(ScriptedFactory(database))
    raw = "v1." + "B" * 43
    token.token_digest = (
        __import__("nebula_api.auth.opaque_tokens", fromlist=["digest_opaque_token"])
        .digest_opaque_token(raw, {1: b"p" * 32}, namespace="refresh")
        .value
    )

    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            auth.refresh(
                refresh_token=raw,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert session.state is LifecycleState.REVOKED
    assert database.executed and database.commits == 1


def test_invalid_refresh_is_audited_without_reflecting_token() -> None:
    audit_session = ScriptedSession()
    auth, _redis = service(ScriptedFactory(audit_session))

    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            auth.refresh(
                refresh_token="malformed-token-canary",  # noqa: S106 - test fixture
                network_prefix="unknown",
                request_id=uuid4(),
            )
        )

    assert isinstance(audit_session.added[0], AuditLog)
    assert "malformed-token-canary" not in repr(audit_session.added[0])


def test_logout_is_idempotent_and_revokes_a_known_session(monkeypatch: pytest.MonkeyPatch) -> None:
    revoked_devices: list[UUID] = []

    async def record_revocation(_session: object, device_id: UUID, _now: datetime) -> int:
        revoked_devices.append(device_id)
        return 0

    monkeypatch.setattr("nebula_api.auth.user_service.revoke_device_credentials", record_revocation)
    token = refresh_record()
    session = active_session()
    raw = "v1." + "C" * 43
    token.token_digest = (
        __import__("nebula_api.auth.opaque_tokens", fromlist=["digest_opaque_token"])
        .digest_opaque_token(raw, {1: b"p" * 32}, namespace="refresh")
        .value
    )
    database = ScriptedSession(scalar_values=(token, session))
    auth, _redis = service(ScriptedFactory(database))

    asyncio.run(auth.logout(refresh_token=raw, request_id=uuid4()))

    assert session.state is LifecycleState.REVOKED
    # Signing out gives up the device's tunnel credentials; Disconnect does not.
    assert revoked_devices == [session.device_id]
    assert database.commits == 1

    other, _ = service(ScriptedFactory(ScriptedSession()))
    asyncio.run(other.logout(refresh_token="bad", request_id=uuid4()))  # noqa: S106


def test_access_principal_rechecks_user_device_and_server_session() -> None:
    session = active_session()
    database = ScriptedSession(scalar_values=(session, user(), device()))
    auth, _redis = service(ScriptedFactory(database))
    token = auth._issue_access(USER_ID, SESSION_ID)

    principal = asyncio.run(auth.authenticate_access_token(token))

    assert principal.user_id == USER_ID
    assert principal.device_id == DEVICE_ID


def test_password_reset_request_issues_only_with_delivery_boundary() -> None:
    database = ScriptedSession(scalar_values=(user(),))
    auth, _redis = service(ScriptedFactory(database))

    issue = asyncio.run(
        auth.request_password_reset(
            identifier="user@example.com",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            enable_delivery=True,
        )
    )

    assert issue is not None and issue.token.startswith("v1.")
    assert issue.token not in repr(issue)
    assert any(isinstance(item, PasswordResetToken) for item in database.added)
    assert any(isinstance(item, EmailDelivery) for item in database.added)


def test_password_reset_confirmation_consumes_once_and_revokes_sessions() -> None:
    raw = "v1." + "D" * 43
    digest = __import__(
        "nebula_api.auth.opaque_tokens", fromlist=["digest_opaque_token"]
    ).digest_opaque_token(raw, {1: b"p" * 32}, namespace="password-reset")
    reset = PasswordResetToken(
        id=uuid4(),
        user_id=USER_ID,
        token_digest=digest.value,
        key_version=1,
        state=TokenState.ACTIVE,
        expires_at=NOW + timedelta(minutes=10),
    )
    database = ScriptedSession(
        scalar_values=(reset, user()),
        scalars_values=((SESSION_ID,),),
    )
    auth, _redis = service(ScriptedFactory(database))

    asyncio.run(
        auth.confirm_password_reset(
            raw_token=raw,
            new_password="replacement-password-canary",  # noqa: S106 - test fixture
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert reset.state is TokenState.CONSUMED
    assert reset.consumed_at == NOW
    assert len(database.executed) == 3
    assert database.commits == 1


def test_login_rate_limit_is_audited_and_device_quota_fails_closed() -> None:
    limited_database = ScriptedSession(scalar_values=(user(),))
    redis = AllowingRedis()
    redis.allowed = False
    limited, _ = service(ScriptedFactory(limited_database), redis)
    with pytest.raises(AuthenticationRateLimited, match="not accepted"):
        asyncio.run(
            limited.login(
                identifier="user@example.com",
                password=PASSWORD,
                device_id=None,
                device_name="Phone",
                platform=DevicePlatform.ANDROID,
                client_version="1.0.0",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert limited_database.commits == 1
    # Refused on the account bucket; the network one is never reached.
    assert [[b.namespace for b in call] for call in redis.buckets] == [["user-account"]]

    quota_database = ScriptedSession(scalar_values=(user(), 3))
    quota, _ = service(ScriptedFactory(quota_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            quota.login(
                identifier="user@example.com",
                password=PASSWORD,
                device_id=None,
                device_name="Phone",
                platform=DevicePlatform.ANDROID,
                client_version="1.0.0",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_refresh_unknown_digest_and_inactive_family_are_generic() -> None:
    raw = "v1." + "E" * 43
    missing_database = ScriptedSession(scalar_values=(None,))
    missing, missing_redis = service(ScriptedFactory(missing_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            missing.refresh(
                refresh_token=raw,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert missing_database.commits == 1
    # The token alone: a network bucket made every device behind one VPN
    # server share ten refreshes.
    assert [[b.namespace for b in call] for call in missing_redis.buckets] == [["refresh-token"]]

    token = refresh_record()
    digest = __import__(
        "nebula_api.auth.opaque_tokens", fromlist=["digest_opaque_token"]
    ).digest_opaque_token(raw, {1: b"p" * 32}, namespace="refresh")
    token.token_digest = digest.value
    expired_session = active_session()
    expired_session.expires_at = NOW
    inactive_database = ScriptedSession(scalar_values=(token, expired_session, user(), device()))
    inactive, _ = service(ScriptedFactory(inactive_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            inactive.refresh(
                refresh_token=raw,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert expired_session.state is LifecycleState.REVOKED
    assert inactive_database.commits == 1


def test_invalid_access_and_expired_reset_are_rejected_without_mutation() -> None:
    invalid_auth, _ = service(ScriptedFactory())
    with pytest.raises(AuthenticationRejected):
        asyncio.run(invalid_auth.authenticate_access_token("not-a-jwt"))

    raw = "v1." + "F" * 43
    digest = __import__(
        "nebula_api.auth.opaque_tokens", fromlist=["digest_opaque_token"]
    ).digest_opaque_token(raw, {1: b"p" * 32}, namespace="password-reset")
    expired = PasswordResetToken(
        id=uuid4(),
        user_id=USER_ID,
        token_digest=digest.value,
        key_version=1,
        state=TokenState.ACTIVE,
        expires_at=NOW,
    )
    database = ScriptedSession(scalar_values=(expired,))
    reset_auth, _ = service(ScriptedFactory(database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            reset_auth.confirm_password_reset(
                raw_token=raw,
                new_password="replacement-password-canary",  # noqa: S106 - test fixture
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_reset_request_without_delivery_creates_no_token_or_email() -> None:
    database = ScriptedSession(scalar_values=(user(),))
    auth, redis = service(ScriptedFactory(database))

    result = asyncio.run(
        auth.request_password_reset(
            identifier="user@example.com",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            enable_delivery=False,
        )
    )

    assert result is None
    assert not any(isinstance(item, PasswordResetToken) for item in database.added)
    assert not any(isinstance(item, EmailDelivery) for item in database.added)
    assert [[b.namespace for b in call] for call in redis.buckets] == [
        ["reset-account"],
        ["reset-request-network"],
    ]
    # The network bucket has its own, higher limit (carrier NAT, VPN exits).
    assert redis.limits[1] == Settings(env="test").user_network_rate_limit
    assert redis.limits[1] > redis.limits[0]


def test_password_reset_confirmation_is_rate_limited_before_hashing_or_database_work() -> None:
    redis = AllowingRedis()
    redis.allowed = False
    auth, _ = service(ScriptedFactory(), redis)

    with pytest.raises(AuthenticationRateLimited):
        asyncio.run(
            auth.confirm_password_reset(
                raw_token="v1." + "A" * 43,
                new_password="replacement-password-canary",  # noqa: S106 - test fixture
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert [[b.namespace for b in call] for call in redis.buckets] == [["reset-token"]]


def _login_remembered(database: ScriptedSession) -> None:
    auth, _redis = service(ScriptedFactory(database))
    asyncio.run(
        auth.login(
            identifier="user@example.com",
            password=PASSWORD,
            device_id=DEVICE_ID,
            device_name="Phone",
            platform=DevicePlatform.ANDROID,
            client_version="2.0.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
            hardware_id="old-install",
        )
    )


def test_a_device_from_before_hardware_ids_gets_its_hash_recorded() -> None:
    # Otherwise an install from before the app sent the id would still be
    # duplicated by its first reinstall.
    existing = device()
    database = ScriptedSession(scalar_values=(user(), existing, None), scalars_values=((),))

    _login_remembered(database)

    assert (
        existing.hardware_hash == hash_hardware_id("old-install", {1: b"p" * 32}, key_version=1)[1]
    )
    assert existing.hardware_key_version == 1


def test_a_hash_another_device_holds_is_not_recorded_twice() -> None:
    existing = device()
    database = ScriptedSession(scalar_values=(user(), existing, uuid4()), scalars_values=((),))

    _login_remembered(database)

    assert existing.hardware_hash is None


def _expired_user() -> User:
    expired = user()
    expired.expires_at = NOW - timedelta(minutes=1)
    return expired


def test_an_expired_account_is_told_so_with_the_right_password() -> None:
    database = ScriptedSession(scalar_values=(_expired_user(),))
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(AccountExpired):
        _login_with_device(auth, None)

    entry = next(item for item in database.added if isinstance(item, AuditLog))
    assert entry.reason_code == "account_expired"
    assert entry.actor_id == USER_ID


def test_an_expired_account_with_a_wrong_password_gets_the_generic_denial() -> None:
    # Without the password, nobody learns that the account exists or expired.
    database = ScriptedSession(scalar_values=(_expired_user(),))
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected) as raised:
        asyncio.run(
            auth.login(
                identifier="user@example.com",
                password="wrong-password-canary",  # noqa: S106 - test fixture
                device_id=None,
                device_name="Phone",
                platform=DevicePlatform.ANDROID,
                client_version="1.0.0",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert not isinstance(raised.value, AccountExpired)


def _principal() -> AuthenticatedUser:
    return AuthenticatedUser(user_id=USER_ID, session_id=SESSION_ID, device_id=DEVICE_ID)


def _audits(database: ScriptedSession) -> list[AuditLog]:
    return [item for item in database.added if isinstance(item, AuditLog)]


class TestChangingThePasswordWhileSignedIn:
    def test_the_new_password_replaces_the_old_and_other_sessions_end(self) -> None:
        account = user()
        old_hash = account.password_hash
        other_session = uuid4()
        database = ScriptedSession(scalar_values=(account,), scalars_values=((other_session,),))
        auth, _ = service(ScriptedFactory(database))

        asyncio.run(
            auth.change_password(
                principal=_principal(),
                current_password=PASSWORD,
                new_password="a-new-password-canary",  # noqa: S106 - test fixture
                request_id=uuid4(),
            )
        )

        assert account.password_hash != old_hash
        # Reset links, then the other session and its refresh tokens.
        assert len(database.executed) == 3
        assert [a.event_code for a in _audits(database)] == ["password_changed"]
        assert database.commits == 1

    def test_a_wrong_current_password_changes_nothing(self) -> None:
        account = user()
        old_hash = account.password_hash
        database = ScriptedSession(scalar_values=(account,))
        auth, _ = service(ScriptedFactory(database))

        with pytest.raises(AuthenticationRejected):
            asyncio.run(
                auth.change_password(
                    principal=_principal(),
                    current_password="not-the-password",  # noqa: S106 - test fixture
                    new_password="a-new-password-canary",  # noqa: S106 - test fixture
                    request_id=uuid4(),
                )
            )

        assert account.password_hash == old_hash
        assert database.executed == []
        assert [(a.event_code, a.outcome) for a in _audits(database)] == [
            ("user_authenticated", "denied")
        ]

    def test_guessing_is_rate_limited(self) -> None:
        database = ScriptedSession()
        redis = AllowingRedis()
        redis.allowed = False
        auth, _ = service(ScriptedFactory(database), redis)

        with pytest.raises(AuthenticationRateLimited):
            asyncio.run(
                auth.change_password(
                    principal=_principal(),
                    current_password=PASSWORD,
                    new_password="a-new-password-canary",  # noqa: S106 - test fixture
                    request_id=uuid4(),
                )
            )
        assert redis.buckets[0][0].namespace == "user-account"


class TestDeletingTheAccount:
    def test_nothing_that_names_the_person_is_left_on_the_rows_kept(self) -> None:
        account = user()
        account.username = "parsa"
        account.username_normalized = "parsa"
        phone = device()
        phone.hardware_hash = b"h" * 32
        phone.hardware_key_version = 1
        database = ScriptedSession(
            scalar_values=(account,),
            # The devices, then each device's WireGuard peers and Xray clients.
            scalars_values=((phone,), (), ()),
        )
        auth, _ = service(ScriptedFactory(database))

        asyncio.run(
            auth.delete_account(principal=_principal(), password=PASSWORD, request_id=uuid4())
        )

        assert "user@example.com" not in account.email
        assert account.email.endswith("@deleted.invalid")
        assert account.username is None and account.username_normalized is None
        assert account.password_hash is None
        assert account.state is AccountState.DISABLED and account.disabled_at == NOW
        assert phone.state is LifecycleState.REVOKED
        assert phone.name == "deleted"
        assert phone.hardware_hash is None
        # Refresh tokens, sessions, activations, reset links, request events,
        # requests, emails, permissions, assignments.
        assert len(database.executed) == 9
        audit = _audits(database)
        assert [(a.event_code, a.reason_code) for a in audit] == [
            ("identity_state_changed", "account_deleted")
        ]
        assert database.commits == 1

    def test_two_deletions_never_share_a_placeholder(self) -> None:
        emails = []
        for _ in range(2):
            account = user()
            database = ScriptedSession(scalar_values=(account,), scalars_values=((),))
            auth, _ = service(ScriptedFactory(database))
            asyncio.run(
                auth.delete_account(principal=_principal(), password=PASSWORD, request_id=uuid4())
            )
            emails.append(account.email)
        assert emails[0] != emails[1]

    def test_a_wrong_password_deletes_nothing(self) -> None:
        account = user()
        database = ScriptedSession(scalar_values=(account,))
        auth, _ = service(ScriptedFactory(database))

        with pytest.raises(AuthenticationRejected):
            asyncio.run(
                auth.delete_account(
                    principal=_principal(),
                    password="not-the-password",  # noqa: S106 - test fixture
                    request_id=uuid4(),
                )
            )

        assert account.email == "user@example.com"
        assert account.state is AccountState.ACTIVE
        assert database.executed == []
