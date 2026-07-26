"""Password, durable MFA, and Redis-backed administrator authentication."""

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from urllib.parse import quote, urlencode
from uuid import UUID, uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.auth.audit import add_audit_event
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.mfa import (
    EncryptedMfaSeed,
    MfaEncryptionError,
    decrypt_mfa_seed,
    encrypt_mfa_seed,
    generate_mfa_seed,
    generate_recovery_codes,
    verify_totp,
)
from nebula_api.auth.opaque_tokens import OpaqueTokenError, digest_opaque_token
from nebula_api.auth.redis_state import (
    AdminSessionRecord,
    IssuedAdminSession,
    RateBucket,
    RedisAuthState,
)
from nebula_api.auth.user_service import AuthenticationRateLimited, AuthenticationRejected
from nebula_api.db.engine import SessionFactory
from nebula_api.identity import normalize_email, normalize_username
from nebula_api.models.identity import (
    AdminMfaRecoveryCode,
    AdminTotpCredential,
    AdminUser,
)
from nebula_api.models.types import AdminRole, AdminState
from nebula_api.passwords import (
    hash_password,
    password_hash_needs_rehash,
    verify_password_or_dummy,
)
from nebula_api.settings import Settings

Clock = Callable[[], datetime]
MfaMethod = Literal["totp", "recovery"]


@dataclass(frozen=True, slots=True, repr=False)
class AdminPasswordChallenge:
    token: str
    next_step: Literal["mfa", "enroll"]
    expires_in_seconds: int

    def __repr__(self) -> str:
        return "AdminPasswordChallenge(token=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AdminEnrollment:
    challenge: str
    expires_in_seconds: int
    base32_secret: str
    provisioning_uri: str

    def __repr__(self) -> str:
        return "AdminEnrollment(challenge=<redacted>, secret=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AdminAuthentication:
    session: IssuedAdminSession
    recovery_codes: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "AdminAuthentication(session=<redacted>, recovery_codes=<redacted>)"


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    admin_id: UUID
    session_id: UUID
    role: AdminRole
    step_up: bool
    mfa_method: MfaMethod


@dataclass(frozen=True, slots=True)
class MfaVerification:
    recovery_code_id: UUID | None = None


class AdminAuthService:
    """Keep privileged identity durable while treating Redis sessions as disposable."""

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

    async def password_challenge(
        self,
        *,
        identifier: str,
        password: str,
        network_prefix: str,
        request_id: UUID,
    ) -> AdminPasswordChallenge:
        normalized = _normalize_admin_identifier(identifier)
        async with self._session_factory() as session:
            admin = await self._find_admin(session, normalized, for_update=True)
            account_key = str(admin.id) if admin is not None else normalized
            allowed = await self._redis.rate_limit(
                (
                    RateBucket("admin-account", account_key),
                    RateBucket("admin-login-network", network_prefix),
                ),
                limit=self._settings.admin_login_rate_limit,
                window_seconds=self._settings.auth_rate_window_seconds,
            )
            if not allowed:
                add_audit_event(
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
            lockout = await self._redis.lockout_status(account_key)
            password_valid = verify_password_or_dummy(
                admin.password_hash if admin is not None else None,
                password,
            )
            eligible = (
                admin is not None
                and admin.state is AdminState.ACTIVE
                and not lockout.locked
                and password_valid
            )
            if not eligible:
                failure = await self._redis.record_admin_failure(
                    account_key,
                    threshold=self._settings.admin_lockout_threshold,
                    lock_seconds=self._settings.admin_lockout_seconds,
                )
                add_audit_event(
                    session,
                    actor_kind="anonymous",
                    actor_id=None,
                    target_kind="auth_attempt",
                    target_id=request_id,
                    event_code=(
                        "auth_lockout_changed" if failure.locked else "admin_authenticated"
                    ),
                    outcome="denied",
                    request_id=request_id,
                    reason_code="invalid_credentials",
                )
                await session.commit()
                raise AuthenticationRejected("Authentication was not accepted")
            if admin is None:
                raise AuthenticationRejected("Authentication was not accepted")
            if password_hash_needs_rehash(admin.password_hash):
                admin.password_hash = hash_password(password)
            credential = await session.scalar(
                select(AdminTotpCredential).where(
                    AdminTotpCredential.admin_user_id == admin.id,
                    AdminTotpCredential.state == "active",
                )
            )
            next_step: Literal["mfa", "enroll"] = "mfa" if credential else "enroll"
            challenge = await self._redis.issue_preauth(
                admin_id=admin.id,
                purpose="login" if next_step == "mfa" else "enroll",
                context=network_prefix,
                ttl_seconds=self._settings.admin_preauth_ttl_minutes * 60,
            )
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin.id,
                target_kind="admin",
                target_id=admin.id,
                event_code="admin_mfa_challenged",
                outcome="succeeded",
                request_id=request_id,
            )
            await session.commit()
        return AdminPasswordChallenge(
            token=challenge.token,
            next_step=next_step,
            expires_in_seconds=challenge.expires_in_seconds,
        )

    async def start_enrollment(
        self,
        *,
        challenge: str,
        network_prefix: str,
        request_id: UUID,
    ) -> AdminEnrollment:
        consumed = await self._redis.consume_preauth(
            challenge,
            purpose="enroll",
            context=network_prefix,
        )
        if consumed is None:
            raise AuthenticationRejected("Authentication was not accepted")
        now = self._now()
        credential_id = uuid4()
        seed = generate_mfa_seed()
        envelope = encrypt_mfa_seed(
            seed,
            admin_id=consumed.admin_id,
            credential_id=credential_id,
            key_version=self._settings.mfa_key_version,
            key_ring=self._keys.mfa_encryption_keys,
        )
        async with self._session_factory() as session:
            admin = await session.scalar(
                select(AdminUser).where(AdminUser.id == consumed.admin_id).with_for_update()
            )
            if admin is None or admin.state is not AdminState.ACTIVE:
                raise AuthenticationRejected("Authentication was not accepted")
            active = await session.scalar(
                select(AdminTotpCredential).where(
                    AdminTotpCredential.admin_user_id == admin.id,
                    AdminTotpCredential.state == "active",
                )
            )
            if active is not None:
                raise AuthenticationRejected("Authentication was not accepted")
            await session.execute(
                update(AdminTotpCredential)
                .where(
                    AdminTotpCredential.admin_user_id == admin.id,
                    AdminTotpCredential.state == "pending",
                )
                .values(
                    state="revoked",
                    secret_ciphertext=None,
                    secret_nonce=None,
                    key_version=None,
                    revoked_at=now,
                )
            )
            session.add(
                AdminTotpCredential(
                    id=credential_id,
                    admin_user_id=admin.id,
                    state="pending",
                    secret_ciphertext=envelope.ciphertext,
                    secret_nonce=envelope.nonce,
                    key_version=envelope.key_version,
                )
            )
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin.id,
                target_kind="admin_totp_credential",
                target_id=credential_id,
                event_code="admin_mfa_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="enrollment_started",
            )
            await session.commit()
            email = admin.email
        confirmation = await self._redis.issue_preauth(
            admin_id=consumed.admin_id,
            purpose="enroll",
            context=network_prefix,
            ttl_seconds=self._settings.admin_preauth_ttl_minutes * 60,
        )
        encoded_seed = base64.b32encode(seed).decode("ascii").rstrip("=")
        label = quote(f"Nebula:{email}", safe="")
        query = urlencode(
            {
                "secret": encoded_seed,
                "issuer": "Nebula",
                "algorithm": "SHA1",
                "digits": "6",
                "period": "30",
            }
        )
        return AdminEnrollment(
            challenge=confirmation.token,
            expires_in_seconds=confirmation.expires_in_seconds,
            base32_secret=encoded_seed,
            provisioning_uri=f"otpauth://totp/{label}?{query}",
        )

    async def confirm_enrollment(
        self,
        *,
        challenge: str,
        code: str,
        network_prefix: str,
        request_id: UUID,
    ) -> AdminAuthentication:
        consumed = await self._consume_mfa_challenge(
            challenge,
            purpose="enroll",
            network_prefix=network_prefix,
        )
        now = self._now()
        issued_session: IssuedAdminSession | None = None
        async with self._session_factory() as session:
            admin = await self._active_admin(session, consumed.admin_id, for_update=True)
            credential = await session.scalar(
                select(AdminTotpCredential)
                .where(
                    AdminTotpCredential.admin_user_id == consumed.admin_id,
                    AdminTotpCredential.state == "pending",
                )
                .with_for_update()
            )
            if admin is None or credential is None:
                raise AuthenticationRejected("Authentication was not accepted")
            accepted_step = self._verify_totp_credential(credential, admin.id, code)
            if accepted_step is None:
                await self._record_mfa_denial(
                    session,
                    admin_id=admin.id,
                    request_id=request_id,
                    reason_code="invalid_mfa",
                )
                raise AuthenticationRejected("Authentication was not accepted")
            credential.state = "active"
            credential.confirmed_at = now
            credential.last_accepted_timestep = accepted_step
            batch = generate_recovery_codes(
                self._keys.token_peppers,
                key_version=self._settings.token_key_version,
            )
            session.add_all(
                AdminMfaRecoveryCode(
                    id=uuid4(),
                    admin_totp_credential_id=credential.id,
                    code_digest=item.value,
                    key_version=item.key_version,
                    state="active",
                )
                for item in batch.digests
            )
            issued_session = await self._new_admin_session(admin.id, "totp")
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin.id,
                target_kind="admin_totp_credential",
                target_id=credential.id,
                event_code="admin_mfa_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="enrollment_confirmed",
            )
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin.id,
                target_kind="admin_session",
                target_id=issued_session.record.session_id,
                event_code="admin_authenticated",
                outcome="succeeded",
                request_id=request_id,
            )
            try:
                await session.commit()
            except BaseException:
                await self._redis.revoke_admin_session(issued_session.session_token)
                raise
        await self._redis.clear_admin_failures(str(consumed.admin_id))
        return AdminAuthentication(
            session=issued_session,
            recovery_codes=batch.take_plaintext_codes(),
        )

    async def verify_mfa(
        self,
        *,
        challenge: str,
        code: str,
        method: MfaMethod,
        network_prefix: str,
        request_id: UUID,
    ) -> AdminAuthentication:
        consumed = await self._consume_mfa_challenge(
            challenge,
            purpose="login",
            network_prefix=network_prefix,
        )
        issued_session: IssuedAdminSession | None = None
        async with self._session_factory() as session:
            admin = await self._active_admin(session, consumed.admin_id, for_update=True)
            credential = await self._active_credential(session, consumed.admin_id, for_update=True)
            if admin is None or credential is None:
                raise AuthenticationRejected("Authentication was not accepted")
            verification = await self._verify_mfa_method(
                session,
                credential=credential,
                admin_id=admin.id,
                code=code,
                method=method,
            )
            if verification is None:
                await self._record_mfa_denial(
                    session,
                    admin_id=admin.id,
                    request_id=request_id,
                    reason_code="invalid_mfa",
                )
                raise AuthenticationRejected("Authentication was not accepted")
            issued_session = await self._new_admin_session(admin.id, method)
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin.id,
                target_kind="admin_session",
                target_id=issued_session.record.session_id,
                event_code="admin_authenticated",
                outcome="succeeded",
                request_id=request_id,
            )
            if verification.recovery_code_id is not None:
                add_audit_event(
                    session,
                    actor_kind="admin",
                    actor_id=admin.id,
                    target_kind="admin_recovery_code",
                    target_id=verification.recovery_code_id,
                    event_code="admin_recovery_code_used",
                    outcome="succeeded",
                    request_id=request_id,
                )
            try:
                await session.commit()
            except BaseException:
                await self._redis.revoke_admin_session(issued_session.session_token)
                raise
        await self._redis.clear_admin_failures(str(consumed.admin_id))
        return AdminAuthentication(session=issued_session)

    async def principal(self, session_token: str) -> AdminPrincipal:
        record = await self._redis.get_admin_session(
            session_token,
            idle_ttl=timedelta(minutes=self._settings.admin_session_ttl_minutes),
        )
        if record is None:
            raise AuthenticationRejected("Authentication was not accepted")
        async with self._session_factory() as session:
            admin = await self._active_admin(session, record.admin_id, for_update=False)
        if admin is None:
            await self._redis.revoke_admin_session(session_token)
            raise AuthenticationRejected("Authentication was not accepted")
        return AdminPrincipal(
            admin_id=admin.id,
            session_id=record.session_id,
            role=admin.role,
            step_up=_is_step_up_fresh(
                record,
                self._now(),
                timedelta(minutes=self._settings.admin_step_up_ttl_minutes),
            ),
            mfa_method=record.mfa_method,
        )

    async def validate_and_rotate_csrf(self, session_token: str, csrf_token: str) -> str:
        replacement = await self._redis.validate_and_rotate_csrf(
            session_token,
            csrf_token,
            idle_ttl=timedelta(minutes=self._settings.admin_session_ttl_minutes),
        )
        if replacement is None:
            raise AuthenticationRejected("Request denied")
        return replacement

    async def step_up(
        self,
        *,
        session_token: str,
        code: str,
        method: MfaMethod,
        network_prefix: str,
        request_id: UUID,
    ) -> AdminAuthentication:
        principal = await self.principal(session_token)
        account_key = str(principal.admin_id)
        if not await self._redis.rate_limit(
            (
                RateBucket("admin-step-up-account", account_key),
                RateBucket("admin-step-up-network", network_prefix),
            ),
            limit=self._settings.admin_mfa_rate_limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            raise AuthenticationRateLimited(self._settings.auth_rate_window_seconds)
        if (await self._redis.lockout_status(account_key)).locked:
            raise AuthenticationRejected("Authentication was not accepted")
        async with self._session_factory() as session:
            admin = await self._active_admin(session, principal.admin_id, for_update=True)
            credential = await self._active_credential(session, principal.admin_id, for_update=True)
            if admin is None or credential is None:
                raise AuthenticationRejected("Authentication was not accepted")
            verification = await self._verify_mfa_method(
                session,
                credential=credential,
                admin_id=admin.id,
                code=code,
                method=method,
            )
            if verification is None:
                await self._record_mfa_denial(
                    session,
                    admin_id=admin.id,
                    request_id=request_id,
                    reason_code="invalid_step_up",
                )
                raise AuthenticationRejected("Authentication was not accepted")
            replacement = await self._redis.rotate_admin_session(
                session_token,
                idle_ttl=timedelta(minutes=self._settings.admin_session_ttl_minutes),
                stepped_up=True,
            )
            if replacement is None:
                raise AuthenticationRejected("Authentication was not accepted")
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin.id,
                target_kind="admin_session",
                target_id=replacement.record.session_id,
                event_code="admin_mfa_challenged",
                outcome="succeeded",
                request_id=request_id,
                reason_code="step_up",
            )
            if verification.recovery_code_id is not None:
                add_audit_event(
                    session,
                    actor_kind="admin",
                    actor_id=admin.id,
                    target_kind="admin_recovery_code",
                    target_id=verification.recovery_code_id,
                    event_code="admin_recovery_code_used",
                    outcome="succeeded",
                    request_id=request_id,
                )
            try:
                await session.commit()
            except BaseException:
                await self._redis.revoke_admin_session(replacement.session_token)
                raise
        await self._redis.clear_admin_failures(account_key)
        return AdminAuthentication(session=replacement)

    async def logout(self, session_token: str, *, request_id: UUID) -> None:
        try:
            principal = await self.principal(session_token)
        except AuthenticationRejected:
            await self._redis.revoke_admin_session(session_token)
            return
        await self._redis.revoke_admin_session(session_token)
        async with self._session_factory() as session:
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=principal.admin_id,
                target_kind="admin_session",
                target_id=principal.session_id,
                event_code="session_revoked",
                outcome="succeeded",
                request_id=request_id,
            )
            await session.commit()

    async def rotate_recovery_codes(
        self,
        *,
        session_token: str,
        request_id: UUID,
    ) -> tuple[str, ...]:
        principal = await self.principal(session_token)
        if not principal.step_up:
            raise AuthenticationRejected("Authentication was not accepted")
        now = self._now()
        async with self._session_factory() as session:
            credential = await self._active_credential(session, principal.admin_id, for_update=True)
            if credential is None:
                raise AuthenticationRejected("Authentication was not accepted")
            await session.execute(
                update(AdminMfaRecoveryCode)
                .where(
                    AdminMfaRecoveryCode.admin_totp_credential_id == credential.id,
                    AdminMfaRecoveryCode.state == "active",
                )
                .values(state="revoked", revoked_at=now)
            )
            batch = generate_recovery_codes(
                self._keys.token_peppers,
                key_version=self._settings.token_key_version,
            )
            session.add_all(
                AdminMfaRecoveryCode(
                    id=uuid4(),
                    admin_totp_credential_id=credential.id,
                    code_digest=item.value,
                    key_version=item.key_version,
                    state="active",
                )
                for item in batch.digests
            )
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=principal.admin_id,
                target_kind="admin_totp_credential",
                target_id=credential.id,
                event_code="admin_mfa_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="recovery_codes_rotated",
            )
            await session.commit()
        return batch.take_plaintext_codes()

    async def _consume_mfa_challenge(
        self,
        challenge: str,
        *,
        purpose: Literal["login", "enroll"],
        network_prefix: str,
    ) -> "ConsumedPreAuth":
        if not await self._redis.rate_limit(
            (
                RateBucket("mfa-challenge", challenge),
                RateBucket("admin-mfa-network", network_prefix),
            ),
            limit=self._settings.admin_mfa_rate_limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            raise AuthenticationRateLimited(self._settings.auth_rate_window_seconds)
        consumed = await self._redis.consume_preauth(
            challenge,
            purpose=purpose,
            context=network_prefix,
        )
        if consumed is None:
            raise AuthenticationRejected("Authentication was not accepted")
        return consumed

    async def _verify_mfa_method(
        self,
        session: AsyncSession,
        *,
        credential: AdminTotpCredential,
        admin_id: UUID,
        code: str,
        method: MfaMethod,
    ) -> MfaVerification | None:
        if method == "totp":
            accepted_step = self._verify_totp_credential(credential, admin_id, code)
            if accepted_step is None:
                return None
            credential.last_accepted_timestep = accepted_step
            return MfaVerification()
        try:
            digest = digest_opaque_token(
                code,
                self._keys.token_peppers,
                namespace="mfa-recovery",
            )
        except (OpaqueTokenError, ValueError):
            return None
        recovery = await session.scalar(
            select(AdminMfaRecoveryCode)
            .where(
                AdminMfaRecoveryCode.admin_totp_credential_id == credential.id,
                AdminMfaRecoveryCode.key_version == digest.key_version,
                AdminMfaRecoveryCode.code_digest == digest.value,
                AdminMfaRecoveryCode.state == "active",
            )
            .with_for_update()
        )
        if recovery is None:
            return None
        recovery.state = "consumed"
        recovery.consumed_at = self._now()
        return MfaVerification(recovery_code_id=recovery.id)

    def _verify_totp_credential(
        self,
        credential: AdminTotpCredential,
        admin_id: UUID,
        code: str,
    ) -> int | None:
        if (
            credential.secret_ciphertext is None
            or credential.secret_nonce is None
            or credential.key_version is None
        ):
            return None
        try:
            seed = decrypt_mfa_seed(
                EncryptedMfaSeed(
                    key_version=credential.key_version,
                    nonce=credential.secret_nonce,
                    ciphertext=credential.secret_ciphertext,
                ),
                admin_id=admin_id,
                credential_id=credential.id,
                key_ring=self._keys.mfa_encryption_keys,
            )
        except (MfaEncryptionError, ValueError):
            return None
        accepted_step = verify_totp(
            seed,
            code,
            clock=self._clock,
            skew=self._settings.totp_allowed_skew_steps,
        )
        if accepted_step is None or (
            credential.last_accepted_timestep is not None
            and accepted_step <= credential.last_accepted_timestep
        ):
            return None
        return accepted_step

    async def _record_mfa_denial(
        self,
        session: AsyncSession,
        *,
        admin_id: UUID,
        request_id: UUID,
        reason_code: str,
    ) -> None:
        failure = await self._redis.record_admin_failure(
            str(admin_id),
            threshold=self._settings.admin_lockout_threshold,
            lock_seconds=self._settings.admin_lockout_seconds,
        )
        add_audit_event(
            session,
            actor_kind="admin",
            actor_id=admin_id,
            target_kind="admin",
            target_id=admin_id,
            event_code=("auth_lockout_changed" if failure.locked else "admin_authenticated"),
            outcome="denied",
            request_id=request_id,
            reason_code=reason_code,
        )
        await session.commit()

    async def _new_admin_session(self, admin_id: UUID, method: MfaMethod) -> IssuedAdminSession:
        return await self._redis.issue_admin_session(
            admin_id=admin_id,
            mfa_method=method,
            idle_ttl=timedelta(minutes=self._settings.admin_session_ttl_minutes),
            absolute_ttl=timedelta(hours=self._settings.admin_session_absolute_ttl_hours),
        )

    async def _find_admin(
        self,
        session: AsyncSession,
        normalized: str,
        *,
        for_update: bool,
    ) -> AdminUser | None:
        statement = select(AdminUser).where(
            or_(
                AdminUser.email_normalized == normalized,
                AdminUser.username_normalized == normalized,
            )
        )
        if for_update:
            statement = statement.with_for_update()
        return cast(AdminUser | None, await session.scalar(statement))

    async def _active_admin(
        self, session: AsyncSession, admin_id: UUID, *, for_update: bool
    ) -> AdminUser | None:
        statement = select(AdminUser).where(
            AdminUser.id == admin_id,
            AdminUser.state == AdminState.ACTIVE,
        )
        if for_update:
            statement = statement.with_for_update()
        return cast(AdminUser | None, await session.scalar(statement))

    async def _active_credential(
        self, session: AsyncSession, admin_id: UUID, *, for_update: bool
    ) -> AdminTotpCredential | None:
        statement = select(AdminTotpCredential).where(
            AdminTotpCredential.admin_user_id == admin_id,
            AdminTotpCredential.state == "active",
        )
        if for_update:
            statement = statement.with_for_update()
        return cast(AdminTotpCredential | None, await session.scalar(statement))

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authentication clock must be timezone aware")
        return value.astimezone(UTC)


def _normalize_admin_identifier(identifier: str) -> str:
    try:
        return normalize_email(identifier) if "@" in identifier else normalize_username(identifier)
    except ValueError:
        return "invalid"


def _is_step_up_fresh(record: AdminSessionRecord, now: datetime, lifetime: timedelta) -> bool:
    return record.step_up_at is not None and record.step_up_at + lifetime > now


# Avoid a runtime import cycle while retaining the precise return type above.
from nebula_api.auth.redis_state import ConsumedPreAuth  # noqa: E402
