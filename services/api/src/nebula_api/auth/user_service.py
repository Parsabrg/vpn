"""Transactional user authentication, refresh rotation, and password recovery."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.auth.access_tokens import AccessTokenClaims, decode_access_token, issue_access_token
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.opaque_tokens import OpaqueTokenError, digest_opaque_token, issue_opaque_token
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.identity import normalize_email, normalize_username
from nebula_api.models.approval import PasswordResetToken
from nebula_api.models.identity import Device, RefreshToken, User, UserSession
from nebula_api.models.operations import AuditLog, EmailDelivery
from nebula_api.models.types import AccountState, DevicePlatform, LifecycleState, TokenState
from nebula_api.passwords import (
    hash_password,
    password_hash_needs_rehash,
    verify_password_or_dummy,
)
from nebula_api.settings import Settings

Clock = Callable[[], datetime]


class PasswordResetDelivery(Protocol):
    async def __call__(self, *, recipient: str, token: str, delivery_id: UUID) -> None: ...


class AuthenticationRejected(Exception):
    """Stable denial used for all invalid user credentials and tokens."""


class AuthenticationRateLimited(AuthenticationRejected):
    """Generic rate denial with a bounded client retry hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Authentication was not accepted")
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True, repr=False)
class UserTokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int

    def __repr__(self) -> str:
        return "UserTokenPair(access_token=<redacted>, refresh_token=<redacted>)"


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    user_id: UUID
    session_id: UUID
    device_id: UUID


@dataclass(frozen=True, slots=True, repr=False)
class PasswordResetIssue:
    recipient: str
    token: str
    delivery_id: UUID

    def __repr__(self) -> str:
        return "PasswordResetIssue(recipient=<redacted>, token=<redacted>)"


class UserAuthService:
    """Own PostgreSQL user-session transitions and their append-only audit events."""

    def __init__(
        self,
        session_factory: SessionFactory,
        redis_state: RedisAuthState,
        key_material: AuthKeyMaterial,
        settings: Settings,
        *,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis_state
        self._keys = key_material
        self._settings = settings
        self._clock = clock

    async def login(
        self,
        *,
        identifier: str,
        password: str,
        device_id: UUID | None,
        device_name: str,
        platform: DevicePlatform,
        client_version: str,
        network_prefix: str,
        request_id: UUID,
    ) -> UserTokenPair:
        normalized = _normalize_identifier(identifier)
        now = self._now()
        async with self._session_factory() as session:
            user = await self._find_user(session, normalized, for_update=True)
            account_bucket = str(user.id) if user is not None else normalized.key
            await self._require_rate_limit(
                session,
                buckets=(
                    RateBucket("user-account", account_bucket),
                    RateBucket("user-login-network", network_prefix),
                ),
                limit=self._settings.user_login_rate_limit,
                request_id=request_id,
                now=now,
            )
            candidate_hash = user.password_hash if user is not None else None
            password_valid = verify_password_or_dummy(candidate_hash, password)
            eligible = user is not None and _user_can_authenticate(user, now)
            if not password_valid or not eligible:
                _add_audit(
                    session,
                    actor_kind="anonymous",
                    actor_id=None,
                    target_kind="auth_attempt",
                    target_id=request_id,
                    event_code="user_authenticated",
                    outcome="denied",
                    request_id=request_id,
                    reason_code="invalid_credentials",
                )
                await session.commit()
                raise AuthenticationRejected("Authentication was not accepted")
            if user is None or user.password_hash is None:
                raise AuthenticationRejected("Authentication was not accepted")
            if password_hash_needs_rehash(user.password_hash):
                user.password_hash = hash_password(password)

            device = await self._resolve_device(
                session,
                user=user,
                device_id=device_id,
                device_name=device_name,
                platform=platform,
                client_version=client_version,
                now=now,
            )
            await self._revoke_active_device_sessions(session, device.id, now=now)
            session_id = uuid4()
            family_expires_at = now + timedelta(days=self._settings.refresh_token_ttl_days)
            user_session = UserSession(
                id=session_id,
                user_id=user.id,
                device_id=device.id,
                family_id=uuid4(),
                state=LifecycleState.ACTIVE,
                expires_at=family_expires_at,
                last_seen_at=now,
            )
            refresh_value, refresh_record = self._new_refresh_token(
                session_id=session_id,
                expires_at=family_expires_at,
            )
            session.add_all((user_session, refresh_record))
            _add_audit(
                session,
                actor_kind="user",
                actor_id=user.id,
                target_kind="user_session",
                target_id=session_id,
                event_code="user_authenticated",
                outcome="succeeded",
                request_id=request_id,
            )
            access_value = self._issue_access(user.id, session_id)
            await session.commit()
        return UserTokenPair(
            access_token=access_value,
            refresh_token=refresh_value,
            access_expires_in=self._settings.access_token_ttl_seconds,
        )

    async def refresh(
        self,
        *,
        refresh_token: str,
        network_prefix: str,
        request_id: UUID,
    ) -> UserTokenPair:
        now = self._now()
        await self._require_rate_limit_without_session(
            buckets=(
                RateBucket("refresh-token", refresh_token),
                RateBucket("user-refresh-network", network_prefix),
            ),
            limit=self._settings.user_login_rate_limit,
        )
        try:
            digest = digest_opaque_token(
                refresh_token,
                self._keys.token_peppers,
                namespace="refresh",
            )
        except (OpaqueTokenError, ValueError):
            await self._audit_unknown_denial(
                request_id=request_id,
                event_code="refresh_rotated",
                reason_code="invalid_token",
            )
            raise AuthenticationRejected("Authentication was not accepted") from None

        async with self._session_factory() as session:
            token = await session.scalar(
                select(RefreshToken)
                .where(
                    RefreshToken.key_version == digest.key_version,
                    RefreshToken.token_digest == digest.value,
                )
                .with_for_update()
            )
            if token is None:
                _add_audit(
                    session,
                    actor_kind="anonymous",
                    actor_id=None,
                    target_kind="auth_attempt",
                    target_id=request_id,
                    event_code="refresh_rotated",
                    outcome="denied",
                    request_id=request_id,
                    reason_code="invalid_token",
                )
                await session.commit()
                raise AuthenticationRejected("Authentication was not accepted")
            user_session = await session.scalar(
                select(UserSession).where(UserSession.id == token.session_id).with_for_update()
            )
            if user_session is None:
                raise AuthenticationRejected("Authentication was not accepted")
            if token.state is TokenState.CONSUMED:
                await self._revoke_session(session, user_session, now=now)
                _add_audit(
                    session,
                    actor_kind="user",
                    actor_id=user_session.user_id,
                    target_kind="user_session",
                    target_id=user_session.id,
                    event_code="refresh_reuse_detected",
                    outcome="denied",
                    request_id=request_id,
                    reason_code="token_reused",
                )
                await session.commit()
                raise AuthenticationRejected("Authentication was not accepted")
            user = await session.scalar(
                select(User).where(User.id == user_session.user_id).with_for_update()
            )
            device = await session.scalar(select(Device).where(Device.id == user_session.device_id))
            if not _refresh_is_eligible(token, user_session, user, device, now):
                await self._revoke_session(session, user_session, now=now)
                _add_audit(
                    session,
                    actor_kind="user",
                    actor_id=user_session.user_id,
                    target_kind="user_session",
                    target_id=user_session.id,
                    event_code="refresh_rotated",
                    outcome="denied",
                    request_id=request_id,
                    reason_code="inactive_session",
                )
                await session.commit()
                raise AuthenticationRejected("Authentication was not accepted")
            if user is None:
                raise AuthenticationRejected("Authentication was not accepted")
            successor_id = uuid4()
            token.state = TokenState.CONSUMED
            token.consumed_at = now
            token.replaced_by_id = successor_id
            # The same-session FK is initially deferred so this update can release
            # the partial unique slot before its successor is inserted.
            await session.flush()
            successor_value, successor = self._new_refresh_token(
                session_id=user_session.id,
                expires_at=min(token.expires_at, user_session.expires_at),
                identifier=successor_id,
            )
            session.add(successor)
            user_session.last_seen_at = now
            _add_audit(
                session,
                actor_kind="user",
                actor_id=user.id,
                target_kind="refresh_token",
                target_id=token.id,
                event_code="refresh_rotated",
                outcome="succeeded",
                request_id=request_id,
            )
            access_value = self._issue_access(user.id, user_session.id)
            await session.commit()
        return UserTokenPair(
            access_token=access_value,
            refresh_token=successor_value,
            access_expires_in=self._settings.access_token_ttl_seconds,
        )

    async def logout(self, *, refresh_token: str, request_id: UUID) -> None:
        now = self._now()
        try:
            digest = digest_opaque_token(
                refresh_token,
                self._keys.token_peppers,
                namespace="refresh",
            )
        except (OpaqueTokenError, ValueError):
            return
        async with self._session_factory() as session:
            token = await session.scalar(
                select(RefreshToken).where(
                    RefreshToken.key_version == digest.key_version,
                    RefreshToken.token_digest == digest.value,
                )
            )
            if token is None:
                return
            user_session = await session.scalar(
                select(UserSession).where(UserSession.id == token.session_id).with_for_update()
            )
            if user_session is None:
                return
            await self._revoke_session(session, user_session, now=now)
            _add_audit(
                session,
                actor_kind="user",
                actor_id=user_session.user_id,
                target_kind="user_session",
                target_id=user_session.id,
                event_code="session_revoked",
                outcome="succeeded",
                request_id=request_id,
            )
            await session.commit()

    async def authenticate_access_token(self, token: str) -> AuthenticatedUser:
        try:
            claims = decode_access_token(
                token,
                issuer=self._settings.jwt_issuer,
                audience=self._settings.jwt_audience,
                verification_keys=self._keys.verification_keys,
                clock=self._clock,
            )
        except ValueError:
            raise AuthenticationRejected("Authentication was not accepted") from None
        return await self._load_principal(claims)

    async def request_password_reset(
        self,
        *,
        identifier: str,
        network_prefix: str,
        request_id: UUID,
        enable_delivery: bool,
    ) -> PasswordResetIssue | None:
        normalized = _normalize_identifier(identifier)
        now = self._now()
        async with self._session_factory() as session:
            user = await self._find_user(session, normalized, for_update=True)
            account_bucket = str(user.id) if user is not None else normalized.key
            await self._require_rate_limit(
                session,
                buckets=(
                    RateBucket("reset-account", account_bucket),
                    RateBucket("reset-request-network", network_prefix),
                ),
                limit=self._settings.password_reset_rate_limit,
                request_id=request_id,
                now=now,
            )
            eligible = user is not None and _user_can_authenticate(user, now)
            issue: PasswordResetIssue | None = None
            if eligible and enable_delivery:
                if user is None:
                    raise AuthenticationRejected("Authentication was not accepted")
                await session.execute(
                    update(PasswordResetToken)
                    .where(
                        PasswordResetToken.user_id == user.id,
                        PasswordResetToken.state == TokenState.ACTIVE,
                    )
                    .values(state=TokenState.REVOKED, revoked_at=now)
                )
                raw_token = issue_opaque_token(self._settings.token_key_version)
                digest = digest_opaque_token(
                    raw_token,
                    self._keys.token_peppers,
                    namespace="password-reset",
                )
                reset_id = uuid4()
                delivery_id = uuid4()
                session.add_all(
                    (
                        PasswordResetToken(
                            id=reset_id,
                            user_id=user.id,
                            token_digest=digest.value,
                            key_version=digest.key_version,
                            state=TokenState.ACTIVE,
                            expires_at=now
                            + timedelta(minutes=self._settings.password_reset_ttl_minutes),
                        ),
                        EmailDelivery(
                            id=delivery_id,
                            deduplication_key=uuid4(),
                            template_code="password_reset",
                            recipient_address=user.email,
                            subject_kind="user",
                            subject_id=user.id,
                            state="pending",
                            attempt_count=0,
                            available_at=now,
                        ),
                    )
                )
                issue = PasswordResetIssue(
                    recipient=user.email,
                    token=raw_token,
                    delivery_id=delivery_id,
                )
            _add_audit(
                session,
                actor_kind="anonymous",
                actor_id=None,
                target_kind="auth_attempt" if user is None else "user",
                target_id=request_id if user is None else user.id,
                event_code="password_reset_requested",
                outcome="succeeded",
                request_id=request_id,
            )
            await session.commit()
            return issue

    async def confirm_password_reset(
        self,
        *,
        raw_token: str,
        new_password: str,
        network_prefix: str,
        request_id: UUID,
    ) -> None:
        await self._require_rate_limit_without_session(
            buckets=(
                RateBucket("reset-token", raw_token),
                RateBucket("reset-confirm-network", network_prefix),
            ),
            limit=self._settings.password_reset_rate_limit,
        )
        now = self._now()
        new_hash = hash_password(new_password)
        try:
            digest = digest_opaque_token(
                raw_token,
                self._keys.token_peppers,
                namespace="password-reset",
            )
        except (OpaqueTokenError, ValueError):
            raise AuthenticationRejected("Authentication was not accepted") from None
        async with self._session_factory() as session:
            reset = await session.scalar(
                select(PasswordResetToken)
                .where(
                    PasswordResetToken.key_version == digest.key_version,
                    PasswordResetToken.token_digest == digest.value,
                )
                .with_for_update()
            )
            if reset is None or reset.state is not TokenState.ACTIVE or reset.expires_at <= now:
                raise AuthenticationRejected("Authentication was not accepted")
            user = await session.scalar(
                select(User).where(User.id == reset.user_id).with_for_update()
            )
            if user is None or not _user_can_authenticate(user, now):
                raise AuthenticationRejected("Authentication was not accepted")
            user.password_hash = new_hash
            reset.state = TokenState.CONSUMED
            reset.consumed_at = now
            await session.execute(
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.id != reset.id,
                    PasswordResetToken.state == TokenState.ACTIVE,
                )
                .values(state=TokenState.REVOKED, revoked_at=now)
            )
            await self._revoke_all_user_sessions(session, user.id, now=now)
            _add_audit(
                session,
                actor_kind="user",
                actor_id=user.id,
                target_kind="password_reset_token",
                target_id=reset.id,
                event_code="password_reset_consumed",
                outcome="succeeded",
                request_id=request_id,
            )
            _add_audit(
                session,
                actor_kind="user",
                actor_id=user.id,
                target_kind="user",
                target_id=user.id,
                event_code="password_changed",
                outcome="succeeded",
                request_id=request_id,
            )
            await session.commit()

    async def _load_principal(self, claims: AccessTokenClaims) -> AuthenticatedUser:
        now = self._now()
        async with self._session_factory() as session:
            user_session = await session.scalar(
                select(UserSession).where(
                    UserSession.id == claims.session_id,
                    UserSession.user_id == claims.subject_id,
                )
            )
            if user_session is None:
                raise AuthenticationRejected("Authentication was not accepted")
            user = await session.scalar(select(User).where(User.id == claims.subject_id))
            device = await session.scalar(select(Device).where(Device.id == user_session.device_id))
            if not _session_is_eligible(user_session, user, device, now):
                raise AuthenticationRejected("Authentication was not accepted")
            return AuthenticatedUser(
                user_id=claims.subject_id,
                session_id=claims.session_id,
                device_id=user_session.device_id,
            )

    async def _find_user(
        self,
        session: AsyncSession,
        normalized: "NormalizedIdentifier",
        *,
        for_update: bool,
    ) -> User | None:
        statement = select(User).where(
            or_(
                User.email_normalized == normalized.key,
                User.username_normalized == normalized.key,
            )
        )
        if for_update:
            statement = statement.with_for_update()
        return cast(User | None, await session.scalar(statement))

    async def _resolve_device(
        self,
        session: AsyncSession,
        *,
        user: User,
        device_id: UUID | None,
        device_name: str,
        platform: DevicePlatform,
        client_version: str,
        now: datetime,
    ) -> Device:
        if device_id is not None:
            device = await session.scalar(
                select(Device)
                .where(Device.id == device_id, Device.user_id == user.id)
                .with_for_update()
            )
            if device is None or device.state is not LifecycleState.ACTIVE:
                raise AuthenticationRejected("Authentication was not accepted")
            device.name = device_name
            device.platform = platform
            device.client_version = client_version
            return device
        active_devices = await session.scalar(
            select(func.count())
            .select_from(Device)
            .where(Device.user_id == user.id, Device.state == LifecycleState.ACTIVE)
        )
        if active_devices is None or active_devices >= user.device_limit:
            raise AuthenticationRejected("Authentication was not accepted")
        device = Device(
            id=uuid4(),
            user_id=user.id,
            name=device_name,
            platform=platform,
            client_version=client_version,
            state=LifecycleState.ACTIVE,
            revoked_at=None,
        )
        session.add(device)
        return device

    async def _revoke_active_device_sessions(
        self, session: AsyncSession, device_id: UUID, *, now: datetime
    ) -> None:
        session_ids = list(
            (
                await session.scalars(
                    select(UserSession.id)
                    .where(
                        UserSession.device_id == device_id,
                        UserSession.state == LifecycleState.ACTIVE,
                    )
                    .with_for_update()
                )
            ).all()
        )
        if not session_ids:
            return
        await session.execute(
            update(UserSession)
            .where(UserSession.id.in_(session_ids))
            .values(state=LifecycleState.REVOKED, revoked_at=now)
        )
        await session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id.in_(session_ids),
                RefreshToken.state == TokenState.ACTIVE,
            )
            .values(state=TokenState.REVOKED, revoked_at=now)
        )

    async def _revoke_session(
        self, session: AsyncSession, user_session: UserSession, *, now: datetime
    ) -> None:
        if user_session.state is LifecycleState.ACTIVE:
            user_session.state = LifecycleState.REVOKED
            user_session.revoked_at = now
        await session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id == user_session.id,
                RefreshToken.state == TokenState.ACTIVE,
            )
            .values(state=TokenState.REVOKED, revoked_at=now)
        )

    async def _revoke_all_user_sessions(
        self, session: AsyncSession, user_id: UUID, *, now: datetime
    ) -> None:
        session_ids = list(
            (
                await session.scalars(
                    select(UserSession.id).where(UserSession.user_id == user_id).with_for_update()
                )
            ).all()
        )
        if session_ids:
            await session.execute(
                update(UserSession)
                .where(
                    UserSession.id.in_(session_ids),
                    UserSession.state == LifecycleState.ACTIVE,
                )
                .values(state=LifecycleState.REVOKED, revoked_at=now)
            )
            await session.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.session_id.in_(session_ids),
                    RefreshToken.state == TokenState.ACTIVE,
                )
                .values(state=TokenState.REVOKED, revoked_at=now)
            )

    def _new_refresh_token(
        self,
        *,
        session_id: UUID,
        expires_at: datetime,
        identifier: UUID | None = None,
    ) -> tuple[str, RefreshToken]:
        value = issue_opaque_token(self._settings.token_key_version)
        digest = digest_opaque_token(value, self._keys.token_peppers, namespace="refresh")
        return value, RefreshToken(
            id=identifier or uuid4(),
            session_id=session_id,
            token_digest=digest.value,
            key_version=digest.key_version,
            state=TokenState.ACTIVE,
            expires_at=expires_at,
        )

    def _issue_access(self, user_id: UUID, session_id: UUID) -> str:
        return issue_access_token(
            subject_id=user_id,
            session_id=session_id,
            issuer=self._settings.jwt_issuer,
            audience=self._settings.jwt_audience,
            signer=self._keys.jwt_signer,
            key_id=self._settings.jwt_key_id,
            ttl_seconds=self._settings.access_token_ttl_seconds,
            clock=self._clock,
        )

    async def _require_rate_limit(
        self,
        session: AsyncSession,
        *,
        buckets: tuple[RateBucket, ...],
        limit: int,
        request_id: UUID,
        now: datetime,
    ) -> None:
        del now
        if await self._redis.rate_limit(
            buckets,
            limit=limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            return
        _add_audit(
            session,
            actor_kind="anonymous",
            actor_id=None,
            target_kind="auth_attempt",
            target_id=request_id,
            event_code="auth_rate_limited",
            outcome="denied",
            request_id=request_id,
            reason_code="rate_limited",
        )
        await session.commit()
        raise AuthenticationRateLimited(self._settings.auth_rate_window_seconds)

    async def _require_rate_limit_without_session(
        self, *, buckets: tuple[RateBucket, ...], limit: int
    ) -> None:
        if not await self._redis.rate_limit(
            buckets,
            limit=limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            raise AuthenticationRateLimited(self._settings.auth_rate_window_seconds)

    async def _audit_unknown_denial(
        self, *, request_id: UUID, event_code: str, reason_code: str
    ) -> None:
        async with self._session_factory() as session:
            _add_audit(
                session,
                actor_kind="anonymous",
                actor_id=None,
                target_kind="auth_attempt",
                target_id=request_id,
                event_code=event_code,
                outcome="denied",
                request_id=request_id,
                reason_code=reason_code,
            )
            await session.commit()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authentication clock must be timezone aware")
        return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class NormalizedIdentifier:
    key: str


def _normalize_identifier(identifier: str) -> NormalizedIdentifier:
    try:
        key = normalize_email(identifier) if "@" in identifier else normalize_username(identifier)
    except ValueError:
        # Preserve a deterministic bucket for malformed input without retaining it.
        key = "invalid"
    return NormalizedIdentifier(key=key)


def _user_can_authenticate(user: User, now: datetime) -> bool:
    return (
        user.state is AccountState.ACTIVE
        and user.password_hash is not None
        and (user.expires_at is None or user.expires_at > now)
    )


def _session_is_eligible(
    user_session: UserSession,
    user: User | None,
    device: Device | None,
    now: datetime,
) -> bool:
    return (
        user_session.state is LifecycleState.ACTIVE
        and user_session.expires_at > now
        and user is not None
        and _user_can_authenticate(user, now)
        and device is not None
        and device.user_id == user.id
        and device.state is LifecycleState.ACTIVE
    )


def _refresh_is_eligible(
    token: RefreshToken,
    user_session: UserSession,
    user: User | None,
    device: Device | None,
    now: datetime,
) -> bool:
    return (
        token.state is TokenState.ACTIVE
        and token.expires_at > now
        and _session_is_eligible(user_session, user, device, now)
    )


def _add_audit(
    session: AsyncSession,
    *,
    actor_kind: str,
    actor_id: UUID | None,
    target_kind: str,
    target_id: UUID,
    event_code: str,
    outcome: str,
    request_id: UUID,
    reason_code: str | None = None,
) -> None:
    session.add(
        AuditLog(
            id=uuid4(),
            actor_kind=actor_kind,
            actor_id=actor_id,
            target_kind=target_kind,
            target_id=target_id,
            event_code=event_code,
            outcome=outcome,
            request_id=request_id,
            reason_code=reason_code,
        )
    )
