"""Transactional account-request submission, review, and activation lifecycle."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.accounts.email_outbox import (
    EmailOutboxRedisClient,
    EmailOutboxUnavailable,
    stage_email_payload,
)
from nebula_api.auth.audit import add_audit_event
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.opaque_tokens import OpaqueTokenError, digest_opaque_token, issue_opaque_token
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.identity import normalize_email, normalize_username
from nebula_api.models.approval import AccountRequest, AccountRequestEvent, UserActivation
from nebula_api.models.identity import AdminUser, User
from nebula_api.models.operations import EmailDelivery
from nebula_api.models.types import AccountState, AdminState, RequestState, TokenState
from nebula_api.passwords import hash_password
from nebula_api.settings import Settings

Clock = Callable[[], datetime]

_ACTIVATION_NAMESPACE = "activation"
_INVALID_EMAIL_SENTINEL = "invalid"
_NOTIFICATION_PAYLOAD_TTL_SECONDS = 7 * 24 * 3_600
_LOGGER = logging.getLogger(__name__)


class AccountRequestRejected(Exception):
    """Stable denial for invalid, expired, or already-decided requests."""


class AccountRequestRateLimited(AccountRequestRejected):
    """Generic rate denial with a bounded client retry hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Request was not accepted")
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class AccountRequestSummary:
    id: UUID
    email: str
    username: str | None
    state: RequestState
    created_at: datetime


class AccountRequestService:
    """Own PostgreSQL account-request transitions and their append-only audit events."""

    def __init__(
        self,
        session_factory: SessionFactory,
        redis_state: RedisAuthState,
        outbox_client: EmailOutboxRedisClient,
        key_material: AuthKeyMaterial,
        settings: Settings,
        *,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis_state
        self._outbox_client = outbox_client
        self._keys = key_material
        self._settings = settings
        self._clock = clock

    async def submit_request(
        self,
        *,
        email: str,
        username: str | None,
        network_prefix: str,
        request_id: UUID,
    ) -> None:
        now = self._now()
        normalized_email = _normalized_email_or_sentinel(email)
        async with self._session_factory() as session:
            await self._require_rate_limit(
                session,
                buckets=(
                    RateBucket("account-request-email", normalized_email),
                    RateBucket("account-request-network", network_prefix),
                ),
                limit=self._settings.account_request_rate_limit,
                request_id=request_id,
            )
            if normalized_email == _INVALID_EMAIL_SENTINEL:
                add_audit_event(
                    session,
                    actor_kind="anonymous",
                    actor_id=None,
                    target_kind="auth_attempt",
                    target_id=request_id,
                    event_code="account_request_changed",
                    outcome="denied",
                    request_id=request_id,
                    reason_code="invalid_email",
                )
                await session.commit()
                return
            normalized_username = normalize_username(username) if username is not None else None
            account_request_id = uuid4()
            session.add(
                AccountRequest(
                    id=account_request_id,
                    email=email,
                    email_normalized=normalized_email,
                    username=username,
                    username_normalized=normalized_username,
                    state=RequestState.PENDING,
                    expires_at=now + timedelta(days=self._settings.account_request_ttl_days),
                )
            )
            session.add(
                AccountRequestEvent(
                    id=uuid4(),
                    request_id=account_request_id,
                    from_state=None,
                    to_state=RequestState.PENDING,
                )
            )
            add_audit_event(
                session,
                actor_kind="anonymous",
                actor_id=None,
                target_kind="account_request",
                target_id=account_request_id,
                event_code="account_request_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="submitted",
            )
            reviewers = (
                await session.scalars(select(AdminUser).where(AdminUser.state == AdminState.ACTIVE))
            ).all()
            notification_ids: list[UUID] = []
            for admin in reviewers:
                delivery_id = uuid4()
                session.add(
                    EmailDelivery(
                        id=delivery_id,
                        deduplication_key=uuid4(),
                        template_code="account_request_review",
                        recipient_address=admin.email,
                        subject_kind="account_request",
                        subject_id=account_request_id,
                        state="pending",
                        attempt_count=0,
                        available_at=now,
                    )
                )
                notification_ids.append(delivery_id)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                # A pending request for this normalized email already exists; stay
                # neutral so submission cannot be used to enumerate registered emails.
                return
        for delivery_id in notification_ids:
            await self._stage_delivery(
                delivery_id=delivery_id,
                payload={
                    "template_code": "account_request_review",
                    "account_request_id": str(account_request_id),
                },
                ttl_seconds=_NOTIFICATION_PAYLOAD_TTL_SECONDS,
            )

    async def list_pending(self) -> list[AccountRequestSummary]:
        async with self._session_factory() as session:
            rows = (
                await session.scalars(
                    select(AccountRequest)
                    .where(AccountRequest.state == RequestState.PENDING)
                    .order_by(AccountRequest.created_at)
                )
            ).all()
            return [_summary(row) for row in rows]

    async def approve(
        self,
        *,
        account_request_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> AccountRequestSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(
                session,
                buckets=(
                    RateBucket("account-request-review-admin", str(admin_id)),
                    RateBucket("account-request-review-network", network_prefix),
                ),
                limit=self._settings.account_request_review_rate_limit,
                request_id=request_id,
            )
            account_request = await session.scalar(
                select(AccountRequest)
                .where(AccountRequest.id == account_request_id)
                .with_for_update()
            )
            if account_request is None:
                raise AccountRequestRejected("Request was not accepted")
            if account_request.state is RequestState.APPROVED:
                summary = _summary(account_request)
                await session.commit()
                return summary
            if account_request.state is not RequestState.PENDING or (
                account_request.expires_at <= now
            ):
                raise AccountRequestRejected("Request was not accepted")

            user_id = uuid4()
            session.add(
                User(
                    id=user_id,
                    email=account_request.email,
                    email_normalized=account_request.email_normalized,
                    username=account_request.username,
                    username_normalized=account_request.username_normalized,
                    state=AccountState.PENDING_ACTIVATION,
                    device_limit=self._settings.default_device_limit,
                )
            )
            account_request.state = RequestState.APPROVED
            account_request.decided_at = now
            account_request.reviewed_by_admin_id = admin_id
            account_request.user_id = user_id

            raw_token = issue_opaque_token(self._settings.token_key_version)
            digest = digest_opaque_token(
                raw_token, self._keys.token_peppers, namespace=_ACTIVATION_NAMESPACE
            )
            activation_expires_at = now + timedelta(hours=self._settings.activation_token_ttl_hours)
            session.add(
                UserActivation(
                    id=uuid4(),
                    account_request_id=account_request.id,
                    user_id=user_id,
                    token_digest=digest.value,
                    key_version=digest.key_version,
                    state=TokenState.ACTIVE,
                    expires_at=activation_expires_at,
                )
            )
            delivery_id = uuid4()
            session.add(
                EmailDelivery(
                    id=delivery_id,
                    deduplication_key=uuid4(),
                    template_code="user_activation",
                    recipient_address=account_request.email,
                    subject_kind="user",
                    subject_id=user_id,
                    state="pending",
                    attempt_count=0,
                    available_at=now,
                )
            )
            session.add(
                AccountRequestEvent(
                    id=uuid4(),
                    request_id=account_request.id,
                    from_state=RequestState.PENDING,
                    to_state=RequestState.APPROVED,
                    actor_admin_id=admin_id,
                    reason_code="approved",
                )
            )
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="account_request",
                target_id=account_request.id,
                event_code="account_request_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="approved",
            )
            summary = _summary(account_request)
            await session.commit()
        await self._stage_delivery(
            delivery_id=delivery_id,
            payload={
                "template_code": "user_activation",
                "token": raw_token,
                "expires_at": activation_expires_at.isoformat(),
            },
            ttl_seconds=self._settings.activation_token_ttl_hours * 3_600,
        )
        return summary

    async def reject(
        self,
        *,
        account_request_id: UUID,
        admin_id: UUID,
        reason: str | None,
        network_prefix: str,
        request_id: UUID,
    ) -> AccountRequestSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(
                session,
                buckets=(
                    RateBucket("account-request-review-admin", str(admin_id)),
                    RateBucket("account-request-review-network", network_prefix),
                ),
                limit=self._settings.account_request_review_rate_limit,
                request_id=request_id,
            )
            account_request = await session.scalar(
                select(AccountRequest)
                .where(AccountRequest.id == account_request_id)
                .with_for_update()
            )
            if account_request is None:
                raise AccountRequestRejected("Request was not accepted")
            if account_request.state is RequestState.REJECTED:
                summary = _summary(account_request)
                await session.commit()
                return summary
            if account_request.state is not RequestState.PENDING:
                raise AccountRequestRejected("Request was not accepted")

            account_request.state = RequestState.REJECTED
            account_request.decided_at = now
            account_request.reviewed_by_admin_id = admin_id
            session.add(
                AccountRequestEvent(
                    id=uuid4(),
                    request_id=account_request.id,
                    from_state=RequestState.PENDING,
                    to_state=RequestState.REJECTED,
                    actor_admin_id=admin_id,
                    reason_code=reason,
                )
            )
            delivery_id = uuid4()
            session.add(
                EmailDelivery(
                    id=delivery_id,
                    deduplication_key=uuid4(),
                    template_code="request_rejected",
                    recipient_address=account_request.email,
                    subject_kind="account_request",
                    subject_id=account_request.id,
                    state="pending",
                    attempt_count=0,
                    available_at=now,
                )
            )
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="account_request",
                target_id=account_request.id,
                event_code="account_request_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="rejected",
            )
            summary = _summary(account_request)
            await session.commit()
        await self._stage_delivery(
            delivery_id=delivery_id,
            payload={"template_code": "request_rejected"},
            ttl_seconds=_NOTIFICATION_PAYLOAD_TTL_SECONDS,
        )
        return summary

    async def confirm_activation(
        self,
        *,
        raw_token: str,
        new_password: str,
        network_prefix: str,
        request_id: UUID,
    ) -> None:
        await self._require_rate_limit_without_session(
            buckets=(
                RateBucket("activation-token", raw_token),
                RateBucket("activation-confirm-network", network_prefix),
            ),
            limit=self._settings.account_request_rate_limit,
        )
        now = self._now()
        new_hash = hash_password(new_password)
        try:
            digest = digest_opaque_token(
                raw_token, self._keys.token_peppers, namespace=_ACTIVATION_NAMESPACE
            )
        except (OpaqueTokenError, ValueError):
            raise AccountRequestRejected("Request was not accepted") from None
        async with self._session_factory() as session:
            activation = await session.scalar(
                select(UserActivation)
                .where(
                    UserActivation.key_version == digest.key_version,
                    UserActivation.token_digest == digest.value,
                )
                .with_for_update()
            )
            if (
                activation is None
                or activation.state is not TokenState.ACTIVE
                or activation.expires_at <= now
            ):
                raise AccountRequestRejected("Request was not accepted")
            user = await session.scalar(
                select(User).where(User.id == activation.user_id).with_for_update()
            )
            if user is None or user.state is not AccountState.PENDING_ACTIVATION:
                raise AccountRequestRejected("Request was not accepted")
            user.password_hash = new_hash
            user.state = AccountState.ACTIVE
            user.activated_at = now
            activation.state = TokenState.CONSUMED
            activation.consumed_at = now
            await session.execute(
                update(UserActivation)
                .where(
                    UserActivation.user_id == user.id,
                    UserActivation.id != activation.id,
                    UserActivation.state == TokenState.ACTIVE,
                )
                .values(state=TokenState.REVOKED, revoked_at=now)
            )
            add_audit_event(
                session,
                actor_kind="user",
                actor_id=user.id,
                target_kind="user",
                target_id=user.id,
                event_code="identity_state_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="activated",
            )
            await session.commit()

    async def _stage_delivery(
        self,
        *,
        delivery_id: UUID,
        payload: dict[str, str],
        ttl_seconds: int,
    ) -> None:
        try:
            await stage_email_payload(
                self._outbox_client,
                delivery_id=delivery_id,
                payload=payload,
                ttl_seconds=ttl_seconds,
            )
        except EmailOutboxUnavailable:
            # The durable EmailDelivery row already committed; the worker will
            # find no staged payload, mark the row failed, and this is visible
            # for operational retry rather than aborting an otherwise-successful
            # request decision.
            _LOGGER.warning(
                "Email outbox payload could not be staged",
                extra={"delivery_id": str(delivery_id)},
            )

    async def _require_rate_limit(
        self,
        session: AsyncSession,
        *,
        buckets: tuple[RateBucket, ...],
        limit: int,
        request_id: UUID,
    ) -> None:
        if await self._redis.rate_limit(
            buckets,
            limit=limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            return
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
        raise AccountRequestRateLimited(self._settings.auth_rate_window_seconds)

    async def _require_rate_limit_without_session(
        self, *, buckets: tuple[RateBucket, ...], limit: int
    ) -> None:
        if not await self._redis.rate_limit(
            buckets,
            limit=limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            raise AccountRequestRateLimited(self._settings.auth_rate_window_seconds)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("account-request clock must be timezone aware")
        return value.astimezone(UTC)


def _summary(row: AccountRequest) -> AccountRequestSummary:
    return AccountRequestSummary(
        id=row.id,
        email=row.email,
        username=row.username,
        state=row.state,
        created_at=row.created_at,
    )


def _normalized_email_or_sentinel(value: str) -> str:
    try:
        return normalize_email(value)
    except ValueError:
        return _INVALID_EMAIL_SENTINEL
