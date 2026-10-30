"""Transactional user authentication, refresh rotation, and password recovery."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.auth.access_tokens import AccessTokenClaims, decode_access_token, issue_access_token
from nebula_api.auth.device_identity import hardware_id_matches, hash_hardware_id
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.opaque_tokens import OpaqueTokenError, digest_opaque_token, issue_opaque_token
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.auth.session_revocation import (
    revoke_active_device_sessions,
    revoke_all_user_sessions,
    revoke_session,
)
from nebula_api.db.engine import SessionFactory
from nebula_api.identity import normalize_email, normalize_username
from nebula_api.models.approval import PasswordResetToken
from nebula_api.models.identity import Device, RefreshToken, User, UserSession
from nebula_api.models.operations import AuditLog, EmailDelivery
from nebula_api.models.types import AccountState, DevicePlatform, LifecycleState, TokenState
from nebula_api.passwords import (
    hash_password_async,
    password_hash_needs_rehash,
    verify_password_or_dummy_async,
)
from nebula_api.provisioning.revocation import revoke_device_credentials
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


class DeviceLimitReached(AuthenticationRejected):
    """The password was right, but the account has no device slot left.

    Said plainly rather than as the generic denial: the credentials were
    already verified, so this reveals nothing to someone who lacks them, and
    the generic answer left people retyping a correct password.
    """

    def __init__(self) -> None:
        super().__init__("device_limit_reached")


class AccountExpired(AuthenticationRejected):
    """The password was right, but the account's access has ended.

    Like [DeviceLimitReached], only ever raised after the password matched,
    so it tells nothing to someone without it.
    """

    def __init__(self) -> None:
        super().__init__("account_expired")


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
        hardware_id: str | None = None,
    ) -> UserTokenPair:
        normalized = _normalize_identifier(identifier)
        now = self._now()
        async with self._session_factory() as session:
            user = await self._find_user(session, normalized, for_update=True)
            account_bucket = str(user.id) if user is not None else normalized.key
            await self._require_rate_limit(
                session,
                buckets=(RateBucket("user-account", account_bucket),),
                limit=self._settings.user_login_rate_limit,
                request_id=request_id,
                now=now,
            )
            await self._require_rate_limit(
                session,
                buckets=(RateBucket("user-login-network", network_prefix),),
                limit=self._settings.user_network_rate_limit,
                request_id=request_id,
                now=now,
            )
            candidate_hash = user.password_hash if user is not None else None
            password_valid = await verify_password_or_dummy_async(candidate_hash, password)
            eligible = user is not None and _user_can_authenticate(user, now)
            if password_valid and user is not None and _only_expired(user, now):
                _add_audit(
                    session,
                    actor_kind="user",
                    actor_id=user.id,
                    target_kind="user",
                    target_id=user.id,
                    event_code="user_authenticated",
                    outcome="denied",
                    request_id=request_id,
                    reason_code="account_expired",
                )
                await session.commit()
                raise AccountExpired
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
                user.password_hash = await hash_password_async(password)

            device = await self._resolve_device(
                session,
                user=user,
                device_id=device_id,
                device_name=device_name,
                platform=platform,
                client_version=client_version,
                hardware_id=hardware_id,
                request_id=request_id,
                now=now,
            )
            await revoke_active_device_sessions(session, device.id, now=now)
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
            # Flush user_session before adding refresh_record: there is no
            # ORM relationship() between UserSession and RefreshToken, so the
            # unit of work does not otherwise guarantee the insert order,
            # and refresh_tokens' foreign key rejects the reverse order.
            session.add(user_session)
            await session.flush()
            refresh_value, refresh_record = self._new_refresh_token(
                session_id=session_id,
                expires_at=family_expires_at,
            )
            session.add(refresh_record)
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
        # The token alone: it is 256 bits, so guessing is no concern, and a
        # per-network bucket made every device behind one VPN server (whose
        # API calls use the tunnel) share 10 refreshes per 15 minutes.
        del network_prefix
        await self._require_rate_limit_without_session(
            buckets=(RateBucket("refresh-token", refresh_token),),
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
                await revoke_session(session, user_session, now=now)
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
                await revoke_session(session, user_session, now=now)
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
            await revoke_session(session, user_session, now=now)
            # Disconnect keeps the device's credentials, so they survive for
            # the next connect and for offline use; signing out is where the
            # device gives them all up.
            await revoke_device_credentials(session, user_session.device_id, now)
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
                buckets=(RateBucket("reset-account", account_bucket),),
                limit=self._settings.password_reset_rate_limit,
                request_id=request_id,
                now=now,
            )
            await self._require_rate_limit(
                session,
                buckets=(RateBucket("reset-request-network", network_prefix),),
                limit=self._settings.user_network_rate_limit,
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
            buckets=(RateBucket("reset-token", raw_token),),
            limit=self._settings.password_reset_rate_limit,
        )
        await self._require_rate_limit_without_session(
            buckets=(RateBucket("reset-confirm-network", network_prefix),),
            limit=self._settings.user_network_rate_limit,
        )
        now = self._now()
        new_hash = await hash_password_async(new_password)
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
            await revoke_all_user_sessions(session, user.id, now=now)
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
        hardware_id: str | None,
        request_id: UUID,
        now: datetime,
    ) -> Device:
        if device_id is not None:
            device = await session.scalar(
                select(Device)
                .where(Device.id == device_id, Device.user_id == user.id)
                .with_for_update()
            )
            if device is not None and device.state is LifecycleState.ACTIVE:
                device.name = device_name
                device.platform = platform
                device.client_version = client_version
                if hardware_id is not None and device.hardware_hash is None:
                    await self._backfill_hardware(
                        session, user=user, device=device, hardware_id=hardware_id
                    )
                return device
            # Not this account's device, or one it has revoked: register a
            # new one rather than refuse. The password has already been
            # checked, so refusing protects nothing -- the same person can
            # sign in by omitting the id -- and it strands a real case. A
            # phone remembers the id it was given and sends it on every
            # sign-in, so switching that phone to a second account used to
            # fail forever, with the same answer as a wrong password and no
            # audit row to tell the two apart.
            #
            # Nothing about the other account is touched or revealed: its
            # device is not read beyond this account's scope, and this path
            # answers exactly as a sign-in with no id does.
        # A reinstall sends the same hardware id but no device id (its stored
        # one was wiped). Reuse the active device that id already names rather
        # than register a second row for one phone -- the session binds to it,
        # and the app learns the reused id from /v1/auth/me and stores it, so
        # it sends the id directly from then on.
        if hardware_id is not None:
            reused = await self._reuse_by_hardware(
                session,
                user=user,
                hardware_id=hardware_id,
                device_name=device_name,
                platform=platform,
                client_version=client_version,
            )
            if reused is not None:
                return reused
        active_devices = await session.scalar(
            select(func.count())
            .select_from(Device)
            .where(Device.user_id == user.id, Device.state == LifecycleState.ACTIVE)
        )
        if active_devices is None or active_devices >= user.device_limit:
            # The password was right, so unlike the denials above this one is
            # attributed to the account. Without the row, an account at its
            # device limit is indistinguishable from a mistyped password.
            _add_audit(
                session,
                actor_kind="user",
                actor_id=user.id,
                target_kind="user",
                target_id=user.id,
                event_code="user_authenticated",
                outcome="denied",
                request_id=request_id,
                reason_code="device_limit_reached",
            )
            await session.commit()
            raise DeviceLimitReached
        hardware = (
            hash_hardware_id(
                hardware_id, self._keys.token_peppers, key_version=self._settings.token_key_version
            )
            if hardware_id is not None
            else (None, None)
        )
        device = Device(
            id=uuid4(),
            user_id=user.id,
            name=device_name,
            platform=platform,
            client_version=client_version,
            state=LifecycleState.ACTIVE,
            revoked_at=None,
            hardware_key_version=hardware[0],
            hardware_hash=hardware[1],
        )
        session.add(device)
        return device

    async def _backfill_hardware(
        self, session: AsyncSession, *, user: User, device: Device, hardware_id: str
    ) -> None:
        """Record the hardware id on a device registered before it was sent.

        Without this, every install from before the app sent the id keeps a
        device with no hash, and its first reinstall registers a second one.
        Skipped when another active device of the account already has the
        hash -- a duplicate from earlier; the unique index allows only one.
        """

        version, digest = hash_hardware_id(
            hardware_id, self._keys.token_peppers, key_version=self._settings.token_key_version
        )
        taken = await session.scalar(
            select(Device.id).where(
                Device.user_id == user.id,
                Device.state == LifecycleState.ACTIVE,
                Device.hardware_hash == digest,
                Device.id != device.id,
            )
        )
        if taken is None:
            device.hardware_key_version = version
            device.hardware_hash = digest

    async def _reuse_by_hardware(
        self,
        session: AsyncSession,
        *,
        user: User,
        hardware_id: str,
        device_name: str,
        platform: DevicePlatform,
        client_version: str,
    ) -> Device | None:
        """The account's active device for this hardware, refreshed, or None.

        Compared with the pepper version each stored hash names, so a key
        rotation does not strand a device enrolled under an earlier one.
        """

        candidates = (
            await session.scalars(
                select(Device)
                .where(
                    Device.user_id == user.id,
                    Device.state == LifecycleState.ACTIVE,
                    Device.hardware_hash.is_not(None),
                )
                .with_for_update()
            )
        ).all()
        for device in candidates:
            if device.hardware_hash is None or device.hardware_key_version is None:
                continue
            if hardware_id_matches(
                hardware_id,
                stored_hash=device.hardware_hash,
                stored_version=device.hardware_key_version,
                key_ring=self._keys.token_peppers,
            ):
                device.name = device_name
                device.platform = platform
                device.client_version = client_version
                return device
        return None

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


def _only_expired(user: User, now: datetime) -> bool:
    """Would sign in, but for an expiry date that has passed."""

    return (
        user.state is AccountState.ACTIVE
        and user.password_hash is not None
        and user.expires_at is not None
        and user.expires_at <= now
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
