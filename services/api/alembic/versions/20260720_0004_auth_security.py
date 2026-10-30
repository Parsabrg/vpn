"""Add authentication and administrator MFA persistence safeguards.

Revision ID: 20260720_0004
Revises: 20260720_0003
"""

import sqlalchemy as sa

from alembic import op

revision = "20260720_0004"
down_revision = "20260720_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "uq_user_sessions_active_device_id",
        "user_sessions",
        ["device_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )

    op.create_unique_constraint(
        "uq_refresh_tokens_id_session_id",
        "refresh_tokens",
        ["id", "session_id"],
    )
    op.drop_constraint(
        op.f("fk_refresh_tokens_replaced_by_id_refresh_tokens"),
        "refresh_tokens",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_refresh_tokens_replacement_same_session_refresh_tokens",
        "refresh_tokens",
        "refresh_tokens",
        ["replaced_by_id", "session_id"],
        ["id", "session_id"],
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
    )
    op.create_check_constraint(
        op.f("ck_refresh_tokens_consumed_replacement_matches_state"),
        "refresh_tokens",
        "(state = 'consumed') = (replaced_by_id IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_refresh_tokens_not_self_replaced"),
        "refresh_tokens",
        "replaced_by_id IS NULL OR replaced_by_id != id",
    )
    op.create_index(
        "uq_refresh_tokens_active_session_id",
        "refresh_tokens",
        ["session_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )

    op.create_table(
        "admin_totp_credentials",
        sa.Column("admin_user_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("secret_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("key_version", sa.Integer(), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_accepted_timestep", sa.BigInteger(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "secret_ciphertext IS NULL OR octet_length(secret_ciphertext) BETWEEN 17 AND 512",
            name=op.f("ck_admin_totp_credentials_ciphertext_length"),
        ),
        sa.CheckConstraint(
            "confirmed_at IS NULL OR confirmed_at >= created_at",
            name=op.f("ck_admin_totp_credentials_confirmation_after_creation"),
        ),
        sa.CheckConstraint(
            "secret_nonce IS NULL OR octet_length(secret_nonce) = 12",
            name=op.f("ck_admin_totp_credentials_nonce_12_bytes"),
        ),
        sa.CheckConstraint(
            "last_accepted_timestep IS NULL OR last_accepted_timestep >= 0",
            name=op.f("ck_admin_totp_credentials_nonnegative_last_accepted_timestep"),
        ),
        sa.CheckConstraint(
            "state != 'pending' OR last_accepted_timestep IS NULL",
            name=op.f("ck_admin_totp_credentials_pending_has_no_accepted_timestep"),
        ),
        sa.CheckConstraint(
            "key_version IS NULL OR key_version > 0",
            name=op.f("ck_admin_totp_credentials_positive_key_version"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_admin_totp_credentials_revocation_after_creation"),
        ),
        sa.CheckConstraint(
            "(state IN ('pending', 'active') AND secret_ciphertext IS NOT NULL AND "
            "secret_nonce IS NOT NULL AND key_version IS NOT NULL) OR "
            "(state = 'revoked' AND secret_ciphertext IS NULL AND secret_nonce IS NULL AND "
            "key_version IS NULL)",
            name=op.f("ck_admin_totp_credentials_secret_material_shape"),
        ),
        sa.CheckConstraint(
            "(state = 'pending' AND confirmed_at IS NULL AND revoked_at IS NULL) OR "
            "(state = 'active' AND confirmed_at IS NOT NULL AND revoked_at IS NULL) OR "
            "(state = 'revoked' AND revoked_at IS NOT NULL)",
            name=op.f("ck_admin_totp_credentials_state_timestamp_shape"),
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'active', 'revoked')",
            name=op.f("ck_admin_totp_credentials_state_vocabulary"),
        ),
        sa.ForeignKeyConstraint(
            ["admin_user_id"],
            ["admin_users.id"],
            name=op.f("fk_admin_totp_credentials_admin_user_id_admin_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_totp_credentials")),
    )
    op.create_index(
        "ix_admin_totp_credentials_admin_user_id_state",
        "admin_totp_credentials",
        ["admin_user_id", "state"],
        unique=False,
    )
    op.create_index(
        "uq_admin_totp_credentials_active_admin_user_id",
        "admin_totp_credentials",
        ["admin_user_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )
    op.create_index(
        "uq_admin_totp_credentials_pending_admin_user_id",
        "admin_totp_credentials",
        ["admin_user_id"],
        unique=True,
        postgresql_where=sa.text("state = 'pending'"),
    )

    op.create_table(
        "admin_mfa_recovery_codes",
        sa.Column("admin_totp_credential_id", sa.UUID(), nullable=False),
        sa.Column("code_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "octet_length(code_digest) = 32",
            name=op.f("ck_admin_mfa_recovery_codes_code_digest_32_bytes"),
        ),
        sa.CheckConstraint(
            "consumed_at IS NULL OR consumed_at >= created_at",
            name=op.f("ck_admin_mfa_recovery_codes_consumption_after_creation"),
        ),
        sa.CheckConstraint(
            "key_version > 0",
            name=op.f("ck_admin_mfa_recovery_codes_positive_key_version"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_admin_mfa_recovery_codes_revocation_after_creation"),
        ),
        sa.CheckConstraint(
            "(state = 'active' AND consumed_at IS NULL AND revoked_at IS NULL) OR "
            "(state = 'consumed' AND consumed_at IS NOT NULL AND revoked_at IS NULL) OR "
            "(state = 'revoked' AND consumed_at IS NULL AND revoked_at IS NOT NULL)",
            name=op.f("ck_admin_mfa_recovery_codes_state_timestamp_shape"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'consumed', 'revoked')",
            name=op.f("ck_admin_mfa_recovery_codes_state_vocabulary"),
        ),
        sa.ForeignKeyConstraint(
            ["admin_totp_credential_id"],
            ["admin_totp_credentials.id"],
            name=op.f(
                "fk_admin_mfa_recovery_codes_admin_totp_credential_id_admin_totp_credentials"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_mfa_recovery_codes")),
        sa.UniqueConstraint(
            "code_digest",
            name="uq_admin_mfa_recovery_codes_code_digest",
        ),
    )
    op.create_index(
        "ix_admin_mfa_recovery_codes_credential_state",
        "admin_mfa_recovery_codes",
        ["admin_totp_credential_id", "state"],
        unique=False,
    )

    op.drop_constraint(
        op.f("ck_audit_logs_actor_identity_shape"),
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_audit_logs_actor_kind_vocabulary"),
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_audit_logs_event_code_vocabulary"),
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_audit_logs_target_kind_vocabulary"),
        "audit_logs",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_audit_logs_actor_identity_shape"),
        "audit_logs",
        "(actor_kind IN ('anonymous', 'system', 'worker', 'bootstrap') AND "
        "actor_id IS NULL) OR "
        "(actor_kind IN ('user', 'admin', 'agent') AND actor_id IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_audit_logs_actor_kind_vocabulary"),
        "audit_logs",
        "actor_kind IN ('user', 'admin', 'anonymous', 'system', 'worker', 'agent', 'bootstrap')",
    )
    op.create_check_constraint(
        op.f("ck_audit_logs_event_code_vocabulary"),
        "audit_logs",
        "event_code IN ("
        "'admin_seeded', 'identity_state_changed', 'device_state_changed', "
        "'account_request_changed', 'profile_changed', 'permission_changed', "
        "'server_changed', 'capability_changed', 'assignment_changed', "
        "'credential_changed', 'peer_changed', 'operation_changed', 'setting_changed', "
        "'email_delivery_changed', 'user_authenticated', 'admin_authenticated', "
        "'refresh_rotated', 'refresh_reuse_detected', 'session_revoked', "
        "'password_changed', 'password_reset_requested', 'password_reset_consumed', "
        "'admin_mfa_changed', 'admin_mfa_challenged', 'admin_recovery_code_used', "
        "'auth_lockout_changed', 'auth_rate_limited', 'csrf_validation')",
    )
    op.create_check_constraint(
        op.f("ck_audit_logs_target_kind_vocabulary"),
        "audit_logs",
        "target_kind IN ("
        "'user', 'admin', 'auth_attempt', 'user_session', 'admin_session', "
        "'refresh_token', 'password_reset_token', 'admin_totp_credential', "
        "'admin_recovery_code', 'device', 'account_request', 'protocol_profile', "
        "'permission', 'vpn_server', 'server_capability', 'assignment', "
        "'device_credential', 'wireguard_peer', 'xray_client', 'agent_operation', "
        "'setting', 'email_delivery')",
    )
    op.create_index(
        "ix_audit_logs_event_recorded",
        "audit_logs",
        ["event_code", "recorded_at"],
        unique=False,
    )

    # Constraint changes do not rebuild the table or its RLS policies. Reassert the
    # append-only runtime privilege boundary in case deployment grants drifted.
    op.execute("REVOKE UPDATE, DELETE ON TABLE audit_logs FROM nebula_app_runtime")


def downgrade() -> None:
    op.drop_index("ix_audit_logs_event_recorded", table_name="audit_logs")
    op.drop_constraint(
        op.f("ck_audit_logs_actor_identity_shape"),
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_audit_logs_actor_kind_vocabulary"),
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_audit_logs_event_code_vocabulary"),
        "audit_logs",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_audit_logs_target_kind_vocabulary"),
        "audit_logs",
        type_="check",
    )

    # These old allowlists intentionally make downgrade fail rather than silently
    # deleting Phase 1.3 audit evidence when newer values are still present.
    op.create_check_constraint(
        op.f("ck_audit_logs_actor_identity_shape"),
        "audit_logs",
        "(actor_kind IN ('system', 'worker', 'bootstrap') AND actor_id IS NULL) OR "
        "(actor_kind IN ('user', 'admin', 'agent') AND actor_id IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_audit_logs_actor_kind_vocabulary"),
        "audit_logs",
        "actor_kind IN ('user', 'admin', 'system', 'worker', 'agent', 'bootstrap')",
    )
    op.create_check_constraint(
        op.f("ck_audit_logs_event_code_vocabulary"),
        "audit_logs",
        "event_code IN ("
        "'admin_seeded', 'identity_state_changed', 'device_state_changed', "
        "'account_request_changed', 'profile_changed', 'permission_changed', "
        "'server_changed', 'capability_changed', 'assignment_changed', "
        "'credential_changed', 'peer_changed', 'operation_changed', 'setting_changed', "
        "'email_delivery_changed')",
    )
    op.create_check_constraint(
        op.f("ck_audit_logs_target_kind_vocabulary"),
        "audit_logs",
        "target_kind IN ("
        "'user', 'admin', 'device', 'account_request', 'protocol_profile', 'permission', "
        "'vpn_server', 'server_capability', 'assignment', 'device_credential', "
        "'wireguard_peer', 'xray_client', 'agent_operation', 'setting', "
        "'email_delivery')",
    )
    op.execute("REVOKE UPDATE, DELETE ON TABLE audit_logs FROM nebula_app_runtime")

    op.drop_table("admin_mfa_recovery_codes")
    op.drop_table("admin_totp_credentials")

    op.drop_index("uq_refresh_tokens_active_session_id", table_name="refresh_tokens")
    op.drop_constraint(
        op.f("ck_refresh_tokens_not_self_replaced"),
        "refresh_tokens",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_refresh_tokens_consumed_replacement_matches_state"),
        "refresh_tokens",
        type_="check",
    )
    op.drop_constraint(
        "fk_refresh_tokens_replacement_same_session_refresh_tokens",
        "refresh_tokens",
        type_="foreignkey",
    )
    op.create_foreign_key(
        op.f("fk_refresh_tokens_replaced_by_id_refresh_tokens"),
        "refresh_tokens",
        "refresh_tokens",
        ["replaced_by_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.drop_constraint(
        "uq_refresh_tokens_id_session_id",
        "refresh_tokens",
        type_="unique",
    )

    op.drop_index("uq_user_sessions_active_device_id", table_name="user_sessions")
