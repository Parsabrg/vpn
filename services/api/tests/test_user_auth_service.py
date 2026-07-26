import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.auth.user_service import (
    AuthenticationRateLimited,
    AuthenticationRejected,
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

    async def rate_limit(
        self,
        buckets: tuple[RateBucket, ...],
        *,
        limit: int,
        window_seconds: int,
    ) -> bool:
        assert limit > 0 and window_seconds > 0
        self.buckets.append(buckets)
        return self.allowed


def keys() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32})


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


def test_logout_is_idempotent_and_revokes_a_known_session() -> None:
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
    assert [bucket.namespace for bucket in redis.buckets[0]] == [
        "user-account",
        "user-login-network",
    ]

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
    assert [bucket.namespace for bucket in missing_redis.buckets[0]] == [
        "refresh-token",
        "user-refresh-network",
    ]

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
    assert [bucket.namespace for bucket in redis.buckets[0]] == [
        "reset-account",
        "reset-request-network",
    ]


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

    assert [bucket.namespace for bucket in redis.buckets[0]] == [
        "reset-token",
        "reset-confirm-network",
    ]
