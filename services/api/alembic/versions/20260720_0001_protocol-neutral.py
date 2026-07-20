"""Create protocol-neutral identity, approval, and token tables."""

# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260720_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("email_normalized", sa.String(length=320), nullable=False),
        sa.Column("username", sa.String(length=32), nullable=True),
        sa.Column("username_normalized", sa.String(length=32), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column(
            "state",
            sa.Enum(
                "pending_activation",
                "active",
                "suspended",
                "disabled",
                name="account_state",
                native_enum=False,
                create_constraint=True,
                length=24,
            ),
            server_default="pending_activation",
            nullable=False,
        ),
        sa.Column("device_limit", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
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
            "state != 'active' OR (password_hash IS NOT NULL AND activated_at IS NOT NULL)",
            name=op.f("ck_users_active_requires_password_and_activation"),
        ),
        sa.CheckConstraint(
            "(username IS NULL) = (username_normalized IS NULL)",
            name=op.f("ck_users_username_normalization_pair"),
        ),
        sa.CheckConstraint("device_limit > 0", name=op.f("ck_users_positive_device_limit")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email_normalized", name=op.f("uq_users_email_normalized")),
        sa.UniqueConstraint("username_normalized", name=op.f("uq_users_username_normalized")),
    )

    op.create_index("ix_users_state_expires_at", "users", ["state", "expires_at"], unique=False)

    op.create_table(
        "admin_users",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("email_normalized", sa.String(length=320), nullable=False),
        sa.Column("username", sa.String(length=32), nullable=True),
        sa.Column("username_normalized", sa.String(length=32), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "owner",
                "operator",
                "auditor",
                name="admin_role",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="owner",
            nullable=False,
        ),
        sa.Column(
            "state",
            sa.Enum(
                "active",
                "disabled",
                name="admin_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
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
            "(state = 'disabled') = (disabled_at IS NOT NULL)",
            name=op.f("ck_admin_users_disabled_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "(username IS NULL) = (username_normalized IS NULL)",
            name=op.f("ck_admin_users_username_normalization_pair"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_users")),
        sa.UniqueConstraint("email_normalized", name=op.f("uq_admin_users_email_normalized")),
        sa.UniqueConstraint("username_normalized", name=op.f("uq_admin_users_username_normalized")),
    )

    op.create_index("ix_admin_users_role_state", "admin_users", ["role", "state"], unique=False)

    op.create_table(
        "devices",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column(
            "platform",
            sa.Enum(
                "android",
                "windows",
                name="device_platform",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("client_version", sa.String(length=32), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "active",
                "revoked",
                name="device_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="active",
            nullable=False,
        ),
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
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_devices_revoked_timestamp_matches_state"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_devices_user_id_users"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_devices")),
        sa.UniqueConstraint("id", "user_id", name="uq_devices_id_user_id"),
    )

    op.create_index("ix_devices_user_id_state", "devices", ["user_id", "state"], unique=False)

    op.create_table(
        "user_sessions",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("family_id", sa.UUID(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "active",
                "revoked",
                name="session_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
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
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_user_sessions_revoked_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_user_sessions_expiry_after_creation")
        ),
        sa.ForeignKeyConstraint(
            ["device_id", "user_id"],
            ["devices.id", "devices.user_id"],
            name="fk_user_sessions_device_owner_devices",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
        sa.UniqueConstraint("family_id", name=op.f("uq_user_sessions_family_id")),
    )

    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"], unique=False)

    op.create_index(
        "ix_user_sessions_user_id_state", "user_sessions", ["user_id", "state"], unique=False
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("session_id", sa.UUID(), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "active",
                "consumed",
                "revoked",
                "expired",
                name="refresh_token_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.UUID(), nullable=True),
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
            "(state = 'consumed') = (consumed_at IS NOT NULL)",
            name=op.f("ck_refresh_tokens_consumed_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_refresh_tokens_revoked_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_refresh_tokens_expiry_after_creation")
        ),
        sa.CheckConstraint("key_version > 0", name=op.f("ck_refresh_tokens_positive_key_version")),
        sa.CheckConstraint(
            "octet_length(token_digest) = 32", name=op.f("ck_refresh_tokens_token_digest_32_bytes")
        ),
        sa.ForeignKeyConstraint(
            ["replaced_by_id"],
            ["refresh_tokens.id"],
            name=op.f("fk_refresh_tokens_replaced_by_id_refresh_tokens"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["user_sessions.id"],
            name=op.f("fk_refresh_tokens_session_id_user_sessions"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("replaced_by_id", name=op.f("uq_refresh_tokens_replaced_by_id")),
        sa.UniqueConstraint("token_digest", name=op.f("uq_refresh_tokens_token_digest")),
    )

    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"], unique=False)

    op.create_index(
        "ix_refresh_tokens_session_id_state",
        "refresh_tokens",
        ["session_id", "state"],
        unique=False,
    )

    op.create_table(
        "account_requests",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("email_normalized", sa.String(length=320), nullable=False),
        sa.Column("username", sa.String(length=32), nullable=True),
        sa.Column("username_normalized", sa.String(length=32), nullable=True),
        sa.Column(
            "state",
            sa.Enum(
                "pending",
                "approved",
                "rejected",
                "expired",
                name="request_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_admin_id", sa.UUID(), nullable=True),
        sa.Column("user_id", sa.UUID(), nullable=True),
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
            "((state IN ('approved', 'rejected')) = (decided_at IS NOT NULL)) AND ((state IN ('approved', 'rejected')) = (reviewed_by_admin_id IS NOT NULL))",
            name=op.f("ck_account_requests_decision_metadata_matches_state"),
        ),
        sa.CheckConstraint(
            "(state = 'approved') = (user_id IS NOT NULL)",
            name=op.f("ck_account_requests_approved_state_matches_user"),
        ),
        sa.CheckConstraint(
            "(username IS NULL) = (username_normalized IS NULL)",
            name=op.f("ck_account_requests_username_normalization_pair"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_account_requests_expiry_after_creation")
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_admin_id"],
            ["admin_users.id"],
            name=op.f("fk_account_requests_reviewed_by_admin_id_admin_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_account_requests_user_id_users"),
            ondelete="RESTRICT",
            use_alter=True,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_account_requests")),
        sa.UniqueConstraint("id", "user_id", name="uq_account_requests_id_user_id"),
        sa.UniqueConstraint("user_id", name=op.f("uq_account_requests_user_id")),
    )

    op.create_index(
        "ix_account_requests_state_created_at",
        "account_requests",
        ["state", "created_at"],
        unique=False,
    )

    op.create_index(
        "uq_account_requests_pending_email_normalized",
        "account_requests",
        ["email_normalized"],
        unique=True,
        postgresql_where=sa.text("state = 'pending'"),
    )

    op.create_table(
        "account_request_events",
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column(
            "from_state",
            sa.Enum(
                "pending",
                "approved",
                "rejected",
                "expired",
                name="request_event_from_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=True,
        ),
        sa.Column(
            "to_state",
            sa.Enum(
                "pending",
                "approved",
                "rejected",
                "expired",
                name="request_event_to_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("actor_admin_id", sa.UUID(), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "(to_state IN ('approved', 'rejected')) = (actor_admin_id IS NOT NULL)",
            name=op.f("ck_account_request_events_admin_actor_matches_decision"),
        ),
        sa.CheckConstraint(
            "from_state IS NULL OR from_state != to_state",
            name=op.f("ck_account_request_events_state_must_change"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_admin_id"],
            ["admin_users.id"],
            name=op.f("fk_account_request_events_actor_admin_id_admin_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["account_requests.id"],
            name=op.f("fk_account_request_events_request_id_account_requests"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_account_request_events")),
    )

    op.create_index(
        "ix_account_request_events_request_id_created_at",
        "account_request_events",
        ["request_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "user_activations",
        sa.Column("account_request_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "active",
                "consumed",
                "revoked",
                "expired",
                name="activation_token_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
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
            "(state = 'consumed') = (consumed_at IS NOT NULL)",
            name=op.f("ck_user_activations_consumed_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_user_activations_revoked_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_user_activations_expiry_after_creation")
        ),
        sa.CheckConstraint(
            "key_version > 0", name=op.f("ck_user_activations_positive_key_version")
        ),
        sa.CheckConstraint(
            "octet_length(token_digest) = 32",
            name=op.f("ck_user_activations_token_digest_32_bytes"),
        ),
        sa.ForeignKeyConstraint(
            ["account_request_id", "user_id"],
            ["account_requests.id", "account_requests.user_id"],
            name="fk_user_activations_request_user_account_requests",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_activations")),
        sa.UniqueConstraint("token_digest", name=op.f("uq_user_activations_token_digest")),
    )

    op.create_index(
        "ix_user_activations_expires_at", "user_activations", ["expires_at"], unique=False
    )

    op.create_index(
        "uq_user_activations_active_user_id",
        "user_activations",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )

    op.create_table(
        "password_reset_tokens",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "active",
                "consumed",
                "revoked",
                "expired",
                name="password_reset_token_state",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
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
            "(state = 'consumed') = (consumed_at IS NOT NULL)",
            name=op.f("ck_password_reset_tokens_consumed_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "(state = 'revoked') = (revoked_at IS NOT NULL)",
            name=op.f("ck_password_reset_tokens_revoked_timestamp_matches_state"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_password_reset_tokens_expiry_after_creation")
        ),
        sa.CheckConstraint(
            "key_version > 0", name=op.f("ck_password_reset_tokens_positive_key_version")
        ),
        sa.CheckConstraint(
            "octet_length(token_digest) = 32",
            name=op.f("ck_password_reset_tokens_token_digest_32_bytes"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_password_reset_tokens_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_password_reset_tokens")),
        sa.UniqueConstraint("token_digest", name=op.f("uq_password_reset_tokens_token_digest")),
    )

    op.create_index(
        "ix_password_reset_tokens_expires_at", "password_reset_tokens", ["expires_at"], unique=False
    )

    op.create_index(
        "uq_password_reset_tokens_active_user_id",
        "password_reset_tokens",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )


def downgrade() -> None:
    op.drop_table("password_reset_tokens")
    op.drop_table("user_activations")
    op.drop_table("account_request_events")
    op.drop_table("account_requests")
    op.drop_table("refresh_tokens")
    op.drop_table("user_sessions")
    op.drop_table("devices")
    op.drop_table("admin_users")
    op.drop_table("users")
