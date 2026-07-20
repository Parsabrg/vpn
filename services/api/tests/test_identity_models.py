from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    LargeBinary,
    Table,
    UniqueConstraint,
)

from nebula_api.db.base import Base
from nebula_api.models.identity import AdminUser, Device, RefreshToken, User, UserSession
from nebula_api.models.types import AccountState, AdminRole, AdminState, TokenState


def _table(model: type[Base]) -> Table:
    return cast(Table, model.__table__)


def test_identity_tables_have_named_constraints() -> None:
    for model in (User, AdminUser, Device, UserSession, RefreshToken):
        assert all(constraint.name for constraint in _table(model).constraints)


def test_device_exposes_composite_ownership_key() -> None:
    assert "uq_devices_id_user_id" in {constraint.name for constraint in _table(Device).constraints}
    assert any(
        isinstance(constraint, UniqueConstraint)
        and tuple(column.name for column in constraint.columns) == ("id", "user_id")
        for constraint in _table(Device).constraints
    )


def test_session_enforces_device_ownership_and_has_unique_family() -> None:
    ownership_fk = next(
        constraint
        for constraint in _table(UserSession).constraints
        if isinstance(constraint, ForeignKeyConstraint)
        and constraint.name == "fk_user_sessions_device_owner_devices"
    )
    assert tuple(element.target_fullname for element in ownership_fk.elements) == (
        "devices.id",
        "devices.user_id",
    )
    assert ownership_fk.ondelete == "RESTRICT"
    assert _table(UserSession).columns.family_id.unique is True


def test_refresh_tokens_store_only_fixed_digest_and_key_version() -> None:
    columns = _table(RefreshToken).columns
    assert "token_digest" in columns
    assert isinstance(columns.token_digest.type, LargeBinary)
    assert columns.token_digest.type.length == 32
    assert "key_version" in columns
    assert "token" not in columns
    assert "ck_refresh_tokens_token_digest_32_bytes" in {
        constraint.name for constraint in _table(RefreshToken).constraints
    }


def test_sensitive_identity_values_are_absent_from_repr() -> None:
    password_hash = "$argon2id$do-not-log"  # noqa: S105 - inert test sentinel
    admin = AdminUser(
        id=uuid4(),
        email="admin@example.com",
        email_normalized="admin@example.com",
        username=None,
        username_normalized=None,
        password_hash=password_hash,
        role=AdminRole.OWNER,
        state=AdminState.ACTIVE,
    )
    user = User(
        id=uuid4(),
        email="user@example.com",
        email_normalized="user@example.com",
        password_hash=password_hash,
        state=AccountState.ACTIVE,
        device_limit=1,
        activated_at=datetime.now(UTC),
    )

    assert password_hash not in repr(admin)
    assert "admin@example.com" not in repr(admin)
    assert password_hash not in repr(user)
    assert "user@example.com" not in repr(user)


def test_refresh_token_repr_excludes_digest() -> None:
    digest = b"x" * 32
    token = RefreshToken(
        id=uuid4(),
        session_id=uuid4(),
        token_digest=digest,
        key_version=1,
        state=TokenState.ACTIVE,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )

    assert digest.hex() not in repr(token)
    assert any(
        isinstance(constraint, CheckConstraint)
        and constraint.name == "ck_refresh_tokens_positive_key_version"
        for constraint in _table(RefreshToken).constraints
    )
