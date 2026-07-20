from typing import cast

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, LargeBinary, Table
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex

from nebula_api.db.base import Base
from nebula_api.models.approval import (
    AccountRequest,
    AccountRequestEvent,
    PasswordResetToken,
    UserActivation,
)


def _table(model: type[Base]) -> Table:
    return cast(Table, model.__table__)


def test_approval_tables_have_named_constraints() -> None:
    for model in (AccountRequest, AccountRequestEvent, UserActivation, PasswordResetToken):
        assert all(constraint.name for constraint in _table(model).constraints)


def test_pending_request_email_is_partially_unique_in_postgresql() -> None:
    index = next(
        item
        for item in _table(AccountRequest).indexes
        if item.name == "uq_account_requests_pending_email_normalized"
    )
    sql = str(
        CreateIndex(index).compile(
            dialect=postgresql.dialect()  # type: ignore[no-untyped-call]
        )
    )

    assert "UNIQUE INDEX" in sql
    assert "WHERE state = 'pending'" in sql


def test_account_request_has_unique_nullable_approved_user() -> None:
    user_id = _table(AccountRequest).columns.user_id
    assert user_id.nullable is True
    assert user_id.unique is True


def test_activation_enforces_approved_request_user_pair() -> None:
    pair_fk = next(
        constraint
        for constraint in _table(UserActivation).constraints
        if isinstance(constraint, ForeignKeyConstraint)
        and constraint.name == "fk_user_activations_request_user_account_requests"
    )
    assert tuple(element.target_fullname for element in pair_fk.elements) == (
        "account_requests.id",
        "account_requests.user_id",
    )
    assert pair_fk.ondelete == "RESTRICT"


def test_one_active_activation_and_reset_per_user() -> None:
    for model, expected_name in (
        (UserActivation, "uq_user_activations_active_user_id"),
        (PasswordResetToken, "uq_password_reset_tokens_active_user_id"),
    ):
        index = next(item for item in _table(model).indexes if item.name == expected_name)
        sql = str(
            CreateIndex(index).compile(
                dialect=postgresql.dialect()  # type: ignore[no-untyped-call]
            )
        )
        assert "UNIQUE INDEX" in sql
        assert "WHERE state = 'active'" in sql


def test_one_time_tokens_store_fixed_keyed_digests_only() -> None:
    for model in (UserActivation, PasswordResetToken):
        table = _table(model)
        columns = table.columns
        assert isinstance(columns.token_digest.type, LargeBinary)
        assert columns.token_digest.type.length == 32
        assert columns.token_digest.unique is True
        assert "key_version" in columns
        assert "token" not in columns
        assert any(
            "token_digest_32_bytes" in str(constraint.name) for constraint in table.constraints
        )
        assert any(
            isinstance(constraint, CheckConstraint)
            and constraint.name is not None
            and "positive_key_version" in str(constraint.name)
            for constraint in table.constraints
        )
