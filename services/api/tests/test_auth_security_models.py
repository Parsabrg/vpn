from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from sqlalchemy import BigInteger, CheckConstraint, ForeignKeyConstraint, LargeBinary, Table
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.schema import CreateIndex

from nebula_api.models.identity import (
    AdminMfaRecoveryCode,
    AdminTotpCredential,
    RefreshToken,
    UserSession,
)
from nebula_api.models.operations import (
    AUDIT_ACTOR_KINDS,
    AUDIT_EVENT_CODES,
    AUDIT_TARGET_KINDS,
    AuditLog,
)


def _table(model: type[object]) -> Table:
    return cast(Table, model.__table__)  # type: ignore[attr-defined]


def _checks(model: type[object]) -> str:
    return " ".join(
        str(constraint.sqltext)
        for constraint in _table(model).constraints
        if isinstance(constraint, CheckConstraint)
    )


def _index_sql(model: type[object], name: str) -> str:
    index = next(item for item in _table(model).indexes if item.name == name)
    return str(CreateIndex(index).compile(dialect=PGDialect()))  # type: ignore[no-untyped-call]


def test_one_active_session_per_registered_device() -> None:
    sql = _index_sql(UserSession, "uq_user_sessions_active_device_id")

    assert "UNIQUE INDEX" in sql
    assert "(device_id)" in sql
    assert "WHERE state = 'active'" in sql


def test_refresh_rotation_is_unique_and_cannot_cross_sessions() -> None:
    table = _table(RefreshToken)
    replacement_fk = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
        and constraint.name == "fk_refresh_tokens_replacement_same_session_refresh_tokens"
    )

    assert tuple(column.name for column in replacement_fk.columns) == (
        "replaced_by_id",
        "session_id",
    )
    assert tuple(element.target_fullname for element in replacement_fk.elements) == (
        "refresh_tokens.id",
        "refresh_tokens.session_id",
    )
    assert replacement_fk.ondelete == "RESTRICT"
    assert replacement_fk.deferrable
    assert replacement_fk.initially == "DEFERRED"
    assert "consumed') = (replaced_by_id IS NOT NULL" in _checks(RefreshToken)
    assert "replaced_by_id != id" in _checks(RefreshToken)

    sql = _index_sql(RefreshToken, "uq_refresh_tokens_active_session_id")
    assert "UNIQUE INDEX" in sql
    assert "(session_id)" in sql
    assert "WHERE state = 'active'" in sql


def test_totp_credentials_store_a_complete_encrypted_tuple_and_replay_counter() -> None:
    table = _table(AdminTotpCredential)
    columns = table.columns
    checks = _checks(AdminTotpCredential)

    assert isinstance(columns.secret_ciphertext.type, LargeBinary)
    assert isinstance(columns.secret_nonce.type, LargeBinary)
    assert isinstance(columns.last_accepted_timestep.type, BigInteger)
    assert {"secret", "totp_secret", "plaintext_secret"}.isdisjoint(columns.keys())
    assert "secret_ciphertext IS NOT NULL" in checks
    assert "octet_length(secret_nonce) = 12" in checks
    assert "last_accepted_timestep >= 0" in checks
    assert "state = 'active' AND confirmed_at IS NOT NULL" in checks
    assert all(constraint.name for constraint in table.constraints)
    assert all(foreign_key.ondelete == "RESTRICT" for foreign_key in table.foreign_keys)

    for name, state in (
        ("uq_admin_totp_credentials_active_admin_user_id", "active"),
        ("uq_admin_totp_credentials_pending_admin_user_id", "pending"),
    ):
        sql = _index_sql(AdminTotpCredential, name)
        assert "UNIQUE INDEX" in sql
        assert f"WHERE state = '{state}'" in sql


def test_recovery_codes_are_fixed_keyed_digests_with_exact_lifecycle() -> None:
    table = _table(AdminMfaRecoveryCode)
    columns = table.columns
    checks = _checks(AdminMfaRecoveryCode)

    assert isinstance(columns.code_digest.type, LargeBinary)
    assert columns.code_digest.type.length == 32
    assert "code" not in columns
    assert "octet_length(code_digest) = 32" in checks
    assert "key_version > 0" in checks
    assert "state = 'consumed' AND consumed_at IS NOT NULL" in checks
    assert all(constraint.name for constraint in table.constraints)
    assert all(foreign_key.ondelete == "RESTRICT" for foreign_key in table.foreign_keys)


def test_mfa_representations_exclude_encrypted_material_and_digests() -> None:
    identifier = uuid4()
    ciphertext = b"encrypted-totp-with-tag"
    digest = b"r" * 32
    credential = AdminTotpCredential(
        id=identifier,
        admin_user_id=identifier,
        state="active",
        secret_ciphertext=ciphertext,
        secret_nonce=b"n" * 12,
        key_version=1,
        confirmed_at=datetime.now(UTC),
    )
    recovery_code = AdminMfaRecoveryCode(
        id=identifier,
        admin_totp_credential_id=identifier,
        code_digest=digest,
        key_version=1,
        state="active",
    )

    rendered = repr(credential) + repr(recovery_code)
    assert ciphertext.hex() not in rendered
    assert digest.hex() not in rendered


def test_audit_vocabulary_supports_authentication_without_unbounded_payloads() -> None:
    assert "anonymous" in AUDIT_ACTOR_KINDS
    assert {
        "auth_attempt",
        "user_session",
        "admin_session",
        "refresh_token",
        "password_reset_token",
        "admin_totp_credential",
        "admin_recovery_code",
    } <= set(AUDIT_TARGET_KINDS)
    assert {
        "user_authenticated",
        "admin_authenticated",
        "refresh_rotated",
        "refresh_reuse_detected",
        "admin_mfa_challenged",
        "auth_rate_limited",
        "csrf_validation",
    } <= set(AUDIT_EVENT_CODES)
    assert "anonymous" in _checks(AuditLog)
    assert "ix_audit_logs_event_recorded" in {index.name for index in _table(AuditLog).indexes}
