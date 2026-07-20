"""Protocol-neutral user, administrator, device, and session persistence."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

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
)
from sqlalchemy import (
    Enum as SQLAlchemyEnum,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from nebula_api.models.types import (
    AccountState,
    AdminRole,
    AdminState,
    DevicePlatform,
    LifecycleState,
    TokenState,
    values,
)


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


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Approved end-user identity independent of any VPN protocol."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("device_limit > 0", name="positive_device_limit"),
        CheckConstraint(
            "(username IS NULL) = (username_normalized IS NULL)",
            name="username_normalization_pair",
        ),
        CheckConstraint(
            "state != 'active' OR (password_hash IS NOT NULL AND activated_at IS NOT NULL)",
            name="active_requires_password_and_activation",
        ),
        Index("ix_users_state_expires_at", "state", "expires_at"),
    )

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    username: Mapped[str | None] = mapped_column(String(32))
    username_normalized: Mapped[str | None] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    state: Mapped[AccountState] = mapped_column(
        _enum(AccountState, "account_state", 24),
        nullable=False,
        default=AccountState.PENDING_ACTIVATION,
        server_default=AccountState.PENDING_ACTIVATION.value,
    )
    device_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<User id={self.id!s} state={self.state.value}>"


class AdminUser(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Privileged identity stored separately from ordinary users."""

    __tablename__ = "admin_users"
    __table_args__ = (
        CheckConstraint(
            "(username IS NULL) = (username_normalized IS NULL)",
            name="username_normalization_pair",
        ),
        CheckConstraint(
            "(state = 'disabled') = (disabled_at IS NOT NULL)",
            name="disabled_timestamp_matches_state",
        ),
        Index("ix_admin_users_role_state", "role", "state"),
    )

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    username: Mapped[str | None] = mapped_column(String(32))
    username_normalized: Mapped[str | None] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[AdminRole] = mapped_column(
        _enum(AdminRole, "admin_role", 16),
        nullable=False,
        default=AdminRole.OWNER,
        server_default=AdminRole.OWNER.value,
    )
    state: Mapped[AdminState] = mapped_column(
        _enum(AdminState, "admin_state", 16),
        nullable=False,
        default=AdminState.ACTIVE,
        server_default=AdminState.ACTIVE.value,
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<AdminUser id={self.id!s} role={self.role.value} state={self.state.value}>"


class Device(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A registered application installation; protocol credentials live elsewhere."""

    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("id", "user_id", name="uq_devices_id_user_id"),
        CheckConstraint(
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name="revoked_timestamp_matches_state",
        ),
        Index("ix_devices_user_id_state", "user_id", "state"),
    )

    user_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    platform: Mapped[DevicePlatform] = mapped_column(
        _enum(DevicePlatform, "device_platform", 16), nullable=False
    )
    client_version: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[LifecycleState] = mapped_column(
        _enum(LifecycleState, "device_state", 16),
        nullable=False,
        default=LifecycleState.ACTIVE,
        server_default=LifecycleState.ACTIVE.value,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<Device id={self.id!s} user_id={self.user_id!s} state={self.state.value}>"


class UserSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Revocable server-side session bound to one owned device."""

    __tablename__ = "user_sessions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["device_id", "user_id"],
            ["devices.id", "devices.user_id"],
            name="fk_user_sessions_device_owner_devices",
            ondelete="RESTRICT",
        ),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint(
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name="revoked_timestamp_matches_state",
        ),
        Index("ix_user_sessions_user_id_state", "user_id", "state"),
        Index("ix_user_sessions_expires_at", "expires_at"),
    )

    user_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    device_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    family_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), nullable=False, unique=True, default=uuid4
    )
    state: Mapped[LifecycleState] = mapped_column(
        _enum(LifecycleState, "session_state", 16),
        nullable=False,
        default=LifecycleState.ACTIVE,
        server_default=LifecycleState.ACTIVE.value,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<UserSession id={self.id!s} state={self.state.value}>"


class RefreshToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Keyed refresh-token digest supporting rotation and reuse detection."""

    __tablename__ = "refresh_tokens"
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
        Index("ix_refresh_tokens_session_id_state", "session_id", "state"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
    )

    session_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("user_sessions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[TokenState] = mapped_column(
        _enum(TokenState, "refresh_token_state", 16),
        nullable=False,
        default=TokenState.ACTIVE,
        server_default=TokenState.ACTIVE.value,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("refresh_tokens.id", ondelete="RESTRICT"),
        unique=True,
    )

    def __repr__(self) -> str:
        return f"<RefreshToken id={self.id!s} state={self.state.value}>"
