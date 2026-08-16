import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.exc import IntegrityError

from nebula_api.accounts.email_outbox import EmailOutboxRedisClient
from nebula_api.accounts.service import (
    AccountRequestRateLimited,
    AccountRequestRejected,
    AccountRequestService,
)
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.opaque_tokens import digest_opaque_token, issue_opaque_token
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.models.approval import AccountRequest, UserActivation
from nebula_api.models.identity import AdminUser, User
from nebula_api.models.types import AccountState, AdminRole, AdminState, RequestState, TokenState
from nebula_api.settings import Settings

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
REQUEST_ID = UUID("11111111-1111-4111-8111-111111111111")
ADMIN_ID = UUID("22222222-2222-4222-8222-222222222222")
USER_ID = UUID("33333333-3333-4333-8333-333333333333")
NEW_PASSWORD = "a-strong-password-123"  # noqa: S105 - test fixture
ADMIN_PASSWORD_HASH = "hash"  # noqa: S105 - test fixture


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
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        return None


class DuplicateOnCommitSession(ScriptedSession):
    async def commit(self) -> None:
        raise IntegrityError("insert", {}, Exception("duplicate"))


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        if not self.sessions:
            raise AssertionError("unexpected database session")
        return self.sessions.pop(0)


class AllowingRedis:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.buckets: list[tuple[RateBucket, ...]] = []

    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        assert limit > 0 and window_seconds > 0
        self.buckets.append(buckets)
        return self.allowed


class FakeOutboxClient:
    def __init__(self) -> None:
        self.staged: list[tuple[str, str, int, bool]] = []

    async def set(self, name: str, value: str, *, ex: int, nx: bool) -> object:
        self.staged.append((name, value, ex, nx))
        return True


def keys() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32})


def service(
    factory: ScriptedFactory,
    *,
    redis: AllowingRedis | None = None,
    outbox: FakeOutboxClient | None = None,
    key_material: AuthKeyMaterial | None = None,
) -> tuple[AccountRequestService, AllowingRedis, FakeOutboxClient]:
    effective_redis = redis or AllowingRedis()
    effective_outbox = outbox or FakeOutboxClient()
    instance = AccountRequestService(
        cast(SessionFactory, factory),
        cast(RedisAuthState, effective_redis),
        cast(EmailOutboxRedisClient, effective_outbox),
        key_material or keys(),
        Settings(env="test"),
        clock=lambda: NOW,
    )
    return instance, effective_redis, effective_outbox


def admin() -> AdminUser:
    return AdminUser(
        id=ADMIN_ID,
        email="owner@example.com",
        email_normalized="owner@example.com",
        password_hash=ADMIN_PASSWORD_HASH,
        role=AdminRole.OWNER,
        state=AdminState.ACTIVE,
    )


def pending_request(**overrides: object) -> AccountRequest:
    defaults: dict[str, object] = dict(
        id=uuid4(),
        email="new-user@example.com",
        email_normalized="new-user@example.com",
        username=None,
        username_normalized=None,
        state=RequestState.PENDING,
        expires_at=NOW + timedelta(days=7),
        created_at=NOW - timedelta(hours=1),
    )
    defaults.update(overrides)
    return AccountRequest(**defaults)


def pending_user() -> User:
    return User(
        id=USER_ID,
        email="new-user@example.com",
        email_normalized="new-user@example.com",
        state=AccountState.PENDING_ACTIVATION,
        device_limit=3,
    )


def active_activation(*, raw_token: str, keys_material: AuthKeyMaterial) -> UserActivation:
    digest = digest_opaque_token(raw_token, keys_material.token_peppers, namespace="activation")
    return UserActivation(
        id=uuid4(),
        account_request_id=uuid4(),
        user_id=USER_ID,
        token_digest=digest.value,
        key_version=digest.key_version,
        state=TokenState.ACTIVE,
        expires_at=NOW + timedelta(hours=24),
    )


def test_submit_request_creates_pending_request_and_notifies_admins() -> None:
    session = ScriptedSession(scalars_values=[[admin()]])
    factory = ScriptedFactory(session)
    instance, _redis, outbox = service(factory)

    asyncio.run(
        instance.submit_request(
            email="applicant@example.com",
            username="applicant",
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert session.commits == 1
    added_types = {type(item).__name__ for item in session.added}
    assert added_types == {"AccountRequest", "AccountRequestEvent", "AuditLog", "EmailDelivery"}
    assert len(outbox.staged) == 1
    assert outbox.staged[0][3] is True


def test_submit_request_with_invalid_email_records_denial_without_creating_request() -> None:
    session = ScriptedSession()
    factory = ScriptedFactory(session)
    instance, _redis, outbox = service(factory)

    asyncio.run(
        instance.submit_request(
            email="not-an-email",
            username=None,
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert session.commits == 1
    added_types = {type(item).__name__ for item in session.added}
    assert added_types == {"AuditLog"}
    assert outbox.staged == []


def test_submit_request_stays_neutral_on_duplicate_pending_email() -> None:
    session = DuplicateOnCommitSession(scalars_values=[[]])
    factory = ScriptedFactory(session)
    instance, _redis, outbox = service(factory)

    asyncio.run(
        instance.submit_request(
            email="applicant@example.com",
            username=None,
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert outbox.staged == []


def test_submit_request_is_rate_limited() -> None:
    session = ScriptedSession()
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory, redis=AllowingRedis(allowed=False))

    with pytest.raises(AccountRequestRateLimited):
        asyncio.run(
            instance.submit_request(
                email="applicant@example.com",
                username=None,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )
    assert session.commits == 1


def test_list_pending_returns_summaries() -> None:
    request = pending_request()
    session = ScriptedSession(scalars_values=[[request]])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory)

    items = asyncio.run(instance.list_pending())

    assert [item.id for item in items] == [request.id]


def test_approve_creates_user_and_activation_and_stages_email() -> None:
    request = pending_request()
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, outbox = service(factory)

    summary = asyncio.run(
        instance.approve(
            account_request_id=request.id,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert summary.state is RequestState.APPROVED
    assert request.state is RequestState.APPROVED
    assert request.user_id is not None
    added_types = [type(item).__name__ for item in session.added]
    assert added_types.count("User") == 1
    assert added_types.count("UserActivation") == 1
    assert added_types.count("EmailDelivery") == 1
    assert len(outbox.staged) == 1


def test_approve_is_idempotent_for_already_approved_request() -> None:
    request = pending_request(state=RequestState.APPROVED, user_id=USER_ID)
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, outbox = service(factory)

    summary = asyncio.run(
        instance.approve(
            account_request_id=request.id,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert summary.state is RequestState.APPROVED
    assert session.added == []
    assert outbox.staged == []


def test_approve_rejects_unknown_request() -> None:
    session = ScriptedSession(scalar_values=[None])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.approve(
                account_request_id=uuid4(),
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_approve_rejects_already_rejected_request() -> None:
    request = pending_request(state=RequestState.REJECTED)
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.approve(
                account_request_id=request.id,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_approve_rejects_expired_pending_request() -> None:
    request = pending_request(expires_at=NOW - timedelta(minutes=1))
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.approve(
                account_request_id=request.id,
                admin_id=ADMIN_ID,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_reject_marks_request_rejected_and_stages_notification() -> None:
    request = pending_request()
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, outbox = service(factory)

    summary = asyncio.run(
        instance.reject(
            account_request_id=request.id,
            admin_id=ADMIN_ID,
            reason="not eligible",
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert summary.state is RequestState.REJECTED
    assert request.reviewed_by_admin_id == ADMIN_ID
    assert len(outbox.staged) == 1


def test_reject_is_idempotent_for_already_rejected_request() -> None:
    request = pending_request(state=RequestState.REJECTED)
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, outbox = service(factory)

    summary = asyncio.run(
        instance.reject(
            account_request_id=request.id,
            admin_id=ADMIN_ID,
            reason=None,
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert summary.state is RequestState.REJECTED
    assert outbox.staged == []


def test_reject_conflicts_with_already_approved_request() -> None:
    request = pending_request(state=RequestState.APPROVED, user_id=USER_ID)
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.reject(
                account_request_id=request.id,
                admin_id=ADMIN_ID,
                reason=None,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_confirm_activation_activates_user() -> None:
    key_material = keys()
    raw_token = issue_opaque_token(1)
    activation = active_activation(raw_token=raw_token, keys_material=key_material)
    user = pending_user()
    session = ScriptedSession(scalar_values=[activation, user])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory, key_material=key_material)

    asyncio.run(
        instance.confirm_activation(
            raw_token=raw_token,
            new_password=NEW_PASSWORD,
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert user.state is AccountState.ACTIVE
    assert user.activated_at == NOW
    assert activation.state is TokenState.CONSUMED
    assert len(session.executed) == 1


def test_confirm_activation_rejects_malformed_token() -> None:
    session = ScriptedSession()
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.confirm_activation(
                raw_token="not-a-real-token",  # noqa: S106 - test fixture
                new_password=NEW_PASSWORD,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_confirm_activation_rejects_expired_token() -> None:
    key_material = keys()
    raw_token = issue_opaque_token(1)
    activation = active_activation(raw_token=raw_token, keys_material=key_material)
    activation.expires_at = NOW - timedelta(minutes=1)
    session = ScriptedSession(scalar_values=[activation])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory, key_material=key_material)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.confirm_activation(
                raw_token=raw_token,
                new_password=NEW_PASSWORD,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_confirm_activation_rejects_inactive_user_state() -> None:
    key_material = keys()
    raw_token = issue_opaque_token(1)
    activation = active_activation(raw_token=raw_token, keys_material=key_material)
    user = pending_user()
    user.state = AccountState.DISABLED
    session = ScriptedSession(scalar_values=[activation, user])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory, key_material=key_material)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.confirm_activation(
                raw_token=raw_token,
                new_password=NEW_PASSWORD,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_reject_rejects_unknown_request() -> None:
    session = ScriptedSession(scalar_values=[None])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(factory)

    with pytest.raises(AccountRequestRejected):
        asyncio.run(
            instance.reject(
                account_request_id=uuid4(),
                admin_id=ADMIN_ID,
                reason=None,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_approve_logs_and_continues_when_outbox_staging_fails() -> None:
    class FailingOutboxClient:
        async def set(self, name: str, value: str, *, ex: int, nx: bool) -> object:
            raise ConnectionError("redis unavailable")

    request = pending_request()
    session = ScriptedSession(scalar_values=[request])
    factory = ScriptedFactory(session)
    instance, _redis, _outbox = service(
        factory, outbox=cast(FakeOutboxClient, FailingOutboxClient())
    )

    summary = asyncio.run(
        instance.approve(
            account_request_id=request.id,
            admin_id=ADMIN_ID,
            network_prefix="203.0.113.0/24",
            request_id=REQUEST_ID,
        )
    )

    assert summary.state is RequestState.APPROVED


def test_naive_clock_is_rejected() -> None:
    instance = AccountRequestService(
        cast(SessionFactory, ScriptedFactory()),
        cast(RedisAuthState, AllowingRedis()),
        cast(EmailOutboxRedisClient, FakeOutboxClient()),
        keys(),
        Settings(env="test"),
        clock=lambda: datetime(2026, 7, 20, 12, 0),
    )

    with pytest.raises(ValueError, match="timezone aware"):
        asyncio.run(
            instance.submit_request(
                email="applicant@example.com",
                username=None,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )


def test_confirm_activation_is_rate_limited() -> None:
    instance, _redis, _outbox = service(ScriptedFactory(), redis=AllowingRedis(allowed=False))

    with pytest.raises(AccountRequestRateLimited):
        asyncio.run(
            instance.confirm_activation(
                raw_token="v1.anything",  # noqa: S106 - test fixture
                new_password=NEW_PASSWORD,
                network_prefix="203.0.113.0/24",
                request_id=REQUEST_ID,
            )
        )
