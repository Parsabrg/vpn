"""Admin-facing user listing, detail, and step-up-gated lifecycle mutations.

Mutations reuse `auth.session_revocation`'s cascade logic so an admin-initiated
revocation behaves identically to a user's own self-service revocation.
Disable/reactivate only handle the `ACTIVE ⇄ DISABLED` transition;
`PENDING_ACTIVATION` users are out of scope for this action.

There is no free-text reason field on these mutations: unlike
`AccountRequestEvent.reason_code` (an unconstrained column purpose-built for
Phase 1.4), the only per-mutation record here is the generic `AuditLog`,
whose `reason_code` is restricted to a short closed-format string. Admin UX
for an optional note belongs with a future, purpose-built column if needed.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.auth import session_revocation
from nebula_api.auth.audit import add_audit_event
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User, UserSession
from nebula_api.models.types import AccountState, LifecycleState
from nebula_api.settings import Settings

Clock = Callable[[], datetime]

_MAX_LIMIT = 200


class UserManagementRejected(Exception):
    """Stable denial for invalid, not-found, or out-of-scope requests."""


class UserManagementRateLimited(UserManagementRejected):
    """Generic rate denial with a bounded client retry hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Request was not accepted")
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class UserSummary:
    id: UUID
    email: str
    username: str | None
    state: AccountState
    device_limit: int
    expires_at: datetime | None
    activated_at: datetime | None
    disabled_at: datetime | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    id: UUID
    name: str
    platform: str
    client_version: str
    state: LifecycleState
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class UserSessionSummary:
    id: UUID
    device_id: UUID
    state: LifecycleState
    expires_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class UserPage:
    items: list[UserSummary]
    total: int


@dataclass(frozen=True, slots=True)
class UserDetail:
    user: UserSummary
    devices: list[DeviceSummary]
    sessions: list[UserSessionSummary]


class UserManagementService:
    """Own PostgreSQL user-lifecycle transitions and their audit events."""

    def __init__(
        self,
        session_factory: SessionFactory,
        redis_state: RedisAuthState,
        settings: Settings,
        *,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis_state
        self._settings = settings
        self._clock = clock

    async def list_users(
        self,
        *,
        state: str | None,
        email_prefix: str | None,
        username_prefix: str | None,
        limit: int,
        offset: int,
    ) -> UserPage:
        bounded_limit = max(1, min(limit, _MAX_LIMIT))
        bounded_offset = max(0, offset)
        conditions: list[ColumnElement[bool]] = []
        if state is not None:
            conditions.append(User.state == state)
        if email_prefix:
            conditions.append(User.email_normalized.startswith(email_prefix.casefold()))
        if username_prefix:
            conditions.append(User.username_normalized.startswith(username_prefix.casefold()))
        async with self._session_factory() as session:
            statement = (
                select(User)
                .where(*conditions)
                .order_by(User.created_at.desc())
                .limit(bounded_limit)
                .offset(bounded_offset)
            )
            count_statement = select(func.count()).select_from(User).where(*conditions)
            rows = (await session.scalars(statement)).all()
            total = await session.scalar(count_statement)
        return UserPage(items=[_user_summary(row) for row in rows], total=total or 0)

    async def get_user_detail(self, user_id: UUID) -> UserDetail | None:
        async with self._session_factory() as session:
            user = await session.scalar(select(User).where(User.id == user_id))
            if user is None:
                return None
            devices = (
                await session.scalars(
                    select(Device).where(Device.user_id == user_id).order_by(Device.created_at)
                )
            ).all()
            sessions = (
                await session.scalars(
                    select(UserSession)
                    .where(UserSession.user_id == user_id)
                    .order_by(UserSession.created_at)
                )
            ).all()
        return UserDetail(
            user=_user_summary(user),
            devices=[_device_summary(device) for device in devices],
            sessions=[_session_summary(item) for item in sessions],
        )

    async def disable_user(
        self,
        *,
        user_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> UserSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(session, admin_id, network_prefix, request_id)
            user = await session.scalar(select(User).where(User.id == user_id).with_for_update())
            if user is None:
                raise UserManagementRejected("Request was not accepted")
            if user.state is AccountState.DISABLED:
                summary = _user_summary(user)
                await session.commit()
                return summary
            if user.state not in (AccountState.ACTIVE, AccountState.SUSPENDED):
                raise UserManagementRejected("Request was not accepted")
            user.state = AccountState.DISABLED
            user.disabled_at = now
            await session_revocation.revoke_all_user_sessions(session, user.id, now=now)
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="user",
                target_id=user.id,
                event_code="identity_state_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="disabled",
            )
            summary = _user_summary(user)
            await session.commit()
        return summary

    async def reactivate_user(
        self,
        *,
        user_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> UserSummary:
        async with self._session_factory() as session:
            await self._require_rate_limit(session, admin_id, network_prefix, request_id)
            user = await session.scalar(select(User).where(User.id == user_id).with_for_update())
            if user is None:
                raise UserManagementRejected("Request was not accepted")
            if user.state is AccountState.ACTIVE:
                summary = _user_summary(user)
                await session.commit()
                return summary
            if user.state is not AccountState.DISABLED:
                raise UserManagementRejected("Request was not accepted")
            user.state = AccountState.ACTIVE
            user.disabled_at = None
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="user",
                target_id=user.id,
                event_code="identity_state_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="reactivated",
            )
            summary = _user_summary(user)
            await session.commit()
        return summary

    async def revoke_device(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> DeviceSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(session, admin_id, network_prefix, request_id)
            device = await session.scalar(
                select(Device)
                .where(Device.id == device_id, Device.user_id == user_id)
                .with_for_update()
            )
            if device is None:
                raise UserManagementRejected("Request was not accepted")
            if device.state is LifecycleState.REVOKED:
                summary = _device_summary(device)
                await session.commit()
                return summary
            device.state = LifecycleState.REVOKED
            device.revoked_at = now
            await session_revocation.revoke_active_device_sessions(session, device.id, now=now)
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="device",
                target_id=device.id,
                event_code="device_state_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="admin_revoked",
            )
            summary = _device_summary(device)
            await session.commit()
        return summary

    async def revoke_session(
        self,
        *,
        user_id: UUID,
        session_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> UserSessionSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(session, admin_id, network_prefix, request_id)
            user_session = await session.scalar(
                select(UserSession)
                .where(UserSession.id == session_id, UserSession.user_id == user_id)
                .with_for_update()
            )
            if user_session is None:
                raise UserManagementRejected("Request was not accepted")
            if user_session.state is LifecycleState.REVOKED:
                summary = _session_summary(user_session)
                await session.commit()
                return summary
            await session_revocation.revoke_session(session, user_session, now=now)
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="user_session",
                target_id=user_session.id,
                event_code="session_revoked",
                outcome="succeeded",
                request_id=request_id,
                reason_code="admin_revoked",
            )
            summary = _session_summary(user_session)
            await session.commit()
        return summary

    async def _require_rate_limit(
        self,
        session: AsyncSession,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> None:
        if await self._redis.rate_limit(
            (
                RateBucket("admin-user-mutation", str(admin_id)),
                RateBucket("admin-user-mutation-network", network_prefix),
            ),
            limit=self._settings.admin_user_mutation_rate_limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            return
        add_audit_event(
            session,
            actor_kind="admin",
            actor_id=admin_id,
            target_kind="admin",
            target_id=admin_id,
            event_code="auth_rate_limited",
            outcome="denied",
            request_id=request_id,
            reason_code="rate_limited",
        )
        await session.commit()
        raise UserManagementRateLimited(self._settings.auth_rate_window_seconds)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("user-management clock must be timezone aware")
        return value.astimezone(UTC)


def _user_summary(row: User) -> UserSummary:
    return UserSummary(
        id=row.id,
        email=row.email,
        username=row.username,
        state=row.state,
        device_limit=row.device_limit,
        expires_at=row.expires_at,
        activated_at=row.activated_at,
        disabled_at=row.disabled_at,
        created_at=row.created_at,
    )


def _device_summary(row: Device) -> DeviceSummary:
    return DeviceSummary(
        id=row.id,
        name=row.name,
        platform=row.platform.value,
        client_version=row.client_version,
        state=row.state,
        revoked_at=row.revoked_at,
    )


def _session_summary(row: UserSession) -> UserSessionSummary:
    return UserSessionSummary(
        id=row.id,
        device_id=row.device_id,
        state=row.state,
        expires_at=row.expires_at,
        last_seen_at=row.last_seen_at,
        revoked_at=row.revoked_at,
    )
