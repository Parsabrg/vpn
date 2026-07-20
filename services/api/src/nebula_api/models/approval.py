"""Approval, activation, and recovery persistence without plaintext tokens."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy import (
    Enum as SQLAlchemyEnum,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from nebula_api.models.types import RequestState, TokenState, values


def _enum[EnumType: StrEnum](enum_type: type[EnumType], name: str, length: int) -> SQLAlchemyEnum:
    return SQLAlchemyEnum(
        enum_type,
        values_callable=values,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        name=name,
        length=length,
    )


class AccountRequest(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Minimal applicant identity and the idempotent approval result."""

    __tablename__ = "account_requests"
    __table_args__ = (
        UniqueConstraint("id", "user_id", name="uq_account_requests_id_user_id"),
        CheckConstraint(
            "(username IS NULL) = (username_normalized IS NULL)",
            name="username_normalization_pair",
        ),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint(
            "(state = 'approved') = (user_id IS NOT NULL)",
            name="approved_state_matches_user",
        ),
        CheckConstraint(
            "((state IN ('approved', 'rejected')) = (decided_at IS NOT NULL)) AND "
            "((state IN ('approved', 'rejected')) = "
            "(reviewed_by_admin_id IS NOT NULL))",
            name="decision_metadata_matches_state",
        ),
        Index(
            "uq_account_requests_pending_email_normalized",
            "email_normalized",
            unique=True,
            postgresql_where=text("state = 'pending'"),
        ),
        Index("ix_account_requests_state_created_at", "state", "created_at"),
    )

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False)
    username: Mapped[str | None] = mapped_column(String(32))
    username_normalized: Mapped[str | None] = mapped_column(String(32))
    state: Mapped[RequestState] = mapped_column(
        _enum(RequestState, "request_state", 16),
        nullable=False,
        default=RequestState.PENDING,
        server_default=RequestState.PENDING.value,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by_admin_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="RESTRICT"),
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT", use_alter=True),
        unique=True,
    )

    def __repr__(self) -> str:
        return f"<AccountRequest id={self.id!s} state={self.state.value}>"


class AccountRequestEvent(UUIDPrimaryKeyMixin, Base):
    """Append-oriented, narrowly structured request state transition."""

    __tablename__ = "account_request_events"
    __table_args__ = (
        CheckConstraint("from_state IS NULL OR from_state != to_state", name="state_must_change"),
        CheckConstraint(
            "(to_state IN ('approved', 'rejected')) = (actor_admin_id IS NOT NULL)",
            name="admin_actor_matches_decision",
        ),
        Index("ix_account_request_events_request_id_created_at", "request_id", "created_at"),
    )

    request_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("account_requests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    from_state: Mapped[RequestState | None] = mapped_column(
        _enum(RequestState, "request_event_from_state", 16)
    )
    to_state: Mapped[RequestState] = mapped_column(
        _enum(RequestState, "request_event_to_state", 16), nullable=False
    )
    actor_admin_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="RESTRICT"),
    )
    reason_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )

    def __repr__(self) -> str:
        return f"<AccountRequestEvent id={self.id!s} to_state={self.to_state.value}>"


class UserActivation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Single-use activation token digest bound to an approved request and user."""

    __tablename__ = "user_activations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["account_request_id", "user_id"],
            ["account_requests.id", "account_requests.user_id"],
            name="fk_user_activations_request_user_account_requests",
            ondelete="RESTRICT",
        ),
        CheckConstraint("key_version > 0", name="positive_key_version"),
        CheckConstraint("octet_length(token_digest) = 32", name="token_digest_32_bytes"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint(
            "(state = 'consumed') = (consumed_at IS NOT NULL)",
            name="consumed_timestamp_matches_state",
        ),
        CheckConstraint(
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name="revoked_timestamp_matches_state",
        ),
        Index(
            "uq_user_activations_active_user_id",
            "user_id",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
        Index("ix_user_activations_expires_at", "expires_at"),
    )

    account_request_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    user_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[TokenState] = mapped_column(
        _enum(TokenState, "activation_token_state", 16),
        nullable=False,
        default=TokenState.ACTIVE,
        server_default=TokenState.ACTIVE.value,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<UserActivation id={self.id!s} state={self.state.value}>"


class PasswordResetToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Single-use password-reset digest; raw link material is never persisted."""

    __tablename__ = "password_reset_tokens"
    __table_args__ = (
        CheckConstraint("key_version > 0", name="positive_key_version"),
        CheckConstraint("octet_length(token_digest) = 32", name="token_digest_32_bytes"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint(
            "(state = 'consumed') = (consumed_at IS NOT NULL)",
            name="consumed_timestamp_matches_state",
        ),
        CheckConstraint(
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name="revoked_timestamp_matches_state",
        ),
        Index(
            "uq_password_reset_tokens_active_user_id",
            "user_id",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
        Index("ix_password_reset_tokens_expires_at", "expires_at"),
    )

    user_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[TokenState] = mapped_column(
        _enum(TokenState, "password_reset_token_state", 16),
        nullable=False,
        default=TokenState.ACTIVE,
        server_default=TokenState.ACTIVE.value,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<PasswordResetToken id={self.id!s} state={self.state.value}>"
