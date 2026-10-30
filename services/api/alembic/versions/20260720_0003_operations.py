"""Create operations tables and enforce append-only application audit access."""

# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260720_0003"
down_revision: str | None = "20260720_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_operations",
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("idempotency_key", sa.UUID(), nullable=False),
        sa.Column("correlation_id", sa.UUID(), nullable=False),
        sa.Column("operation_kind", sa.String(length=32), nullable=False),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("desired_generation", sa.Integer(), server_default="0", nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
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
            "error_code IS NULL OR error_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name=op.f("ck_agent_operations_error_code_format"),
        ),
        sa.CheckConstraint(
            "operation_kind IN ('provision_device', 'revoke_device', 'enable_device', 'disable_device', 'health', 'reconcile')",
            name=op.f("ck_agent_operations_operation_kind_vocabulary"),
        ),
        sa.CheckConstraint(
            "request_fingerprint ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_agent_operations_request_fingerprint_format"),
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_agent_operations_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "state NOT IN ('succeeded', 'failed', 'cancelled') OR finished_at IS NOT NULL",
            name=op.f("ck_agent_operations_terminal_state_finished"),
        ),
        sa.CheckConstraint(
            "target_kind IN ('device_credential', 'wireguard_peer', 'xray_client', 'server_capability', 'vpn_server')",
            name=op.f("ck_agent_operations_target_kind_vocabulary"),
        ),
        sa.CheckConstraint(
            "attempt_count BETWEEN 0 AND 100", name=op.f("ck_agent_operations_attempt_count_range")
        ),
        sa.CheckConstraint(
            "desired_generation >= 0",
            name=op.f("ck_agent_operations_desired_generation_nonnegative"),
        ),
        sa.CheckConstraint(
            "finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at",
            name=op.f("ck_agent_operations_finish_after_start"),
        ),
        sa.CheckConstraint(
            "started_at IS NULL OR started_at >= requested_at",
            name=op.f("ck_agent_operations_start_after_request"),
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_agent_operations_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_operations")),
        sa.UniqueConstraint("idempotency_key", name="uq_agent_operations_idempotency_key"),
    )

    op.create_index(
        "ix_agent_operations_server_state",
        "agent_operations",
        ["vpn_server_id", "state"],
        unique=False,
    )

    op.create_index(
        "uq_agent_operations_inflight_target",
        "agent_operations",
        ["vpn_server_id", "target_kind", "target_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('pending', 'running')"),
    )

    op.create_table(
        "reconciliation_records",
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("agent_operation_id", sa.UUID(), nullable=True),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("desired_generation", sa.Integer(), nullable=False),
        sa.Column("observed_generation", sa.Integer(), nullable=True),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column(
            "checked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name=op.f("ck_reconciliation_records_error_code_format"),
        ),
        sa.CheckConstraint(
            "outcome IN ('in_sync', 'drift_detected', 'repair_requested', 'repair_succeeded', 'repair_failed', 'ambiguous')",
            name=op.f("ck_reconciliation_records_outcome_vocabulary"),
        ),
        sa.CheckConstraint(
            "target_kind IN ('device_credential', 'wireguard_peer', 'xray_client', 'server_capability', 'vpn_server')",
            name=op.f("ck_reconciliation_records_target_kind_vocabulary"),
        ),
        sa.CheckConstraint(
            "desired_generation >= 0",
            name=op.f("ck_reconciliation_records_desired_generation_nonnegative"),
        ),
        sa.CheckConstraint(
            "observed_generation IS NULL OR observed_generation >= 0",
            name=op.f("ck_reconciliation_records_observed_generation_nonnegative"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_operation_id"],
            ["agent_operations.id"],
            name=op.f("fk_reconciliation_records_agent_operation_id_agent_operations"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_reconciliation_records_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reconciliation_records")),
        sa.UniqueConstraint(
            "vpn_server_id",
            "target_kind",
            "target_id",
            "checked_at",
            name="uq_reconciliation_records_target_check",
        ),
    )

    op.create_index(
        "ix_reconciliation_records_target_checked",
        "reconciliation_records",
        ["target_kind", "target_id", "checked_at"],
        unique=False,
    )

    op.create_table(
        "audit_logs",
        sa.Column("actor_kind", sa.String(length=16), nullable=False),
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("event_code", sa.String(length=40), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("request_id", sa.UUID(), nullable=True),
        sa.Column("correlation_id", sa.UUID(), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "(actor_kind IN ('system', 'worker', 'bootstrap') AND actor_id IS NULL) OR (actor_kind IN ('user', 'admin', 'agent') AND actor_id IS NOT NULL)",
            name=op.f("ck_audit_logs_actor_identity_shape"),
        ),
        sa.CheckConstraint(
            "actor_kind IN ('user', 'admin', 'system', 'worker', 'agent', 'bootstrap')",
            name=op.f("ck_audit_logs_actor_kind_vocabulary"),
        ),
        sa.CheckConstraint(
            "event_code IN ('admin_seeded', 'identity_state_changed', 'device_state_changed', 'account_request_changed', 'profile_changed', 'permission_changed', 'server_changed', 'capability_changed', 'assignment_changed', 'credential_changed', 'peer_changed', 'operation_changed', 'setting_changed', 'email_delivery_changed')",
            name=op.f("ck_audit_logs_event_code_vocabulary"),
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'failed', 'denied')",
            name=op.f("ck_audit_logs_outcome_vocabulary"),
        ),
        sa.CheckConstraint(
            "reason_code IS NULL OR reason_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name=op.f("ck_audit_logs_reason_code_format"),
        ),
        sa.CheckConstraint(
            "target_kind IN ('user', 'admin', 'device', 'account_request', 'protocol_profile', 'permission', 'vpn_server', 'server_capability', 'assignment', 'device_credential', 'wireguard_peer', 'xray_client', 'agent_operation', 'setting', 'email_delivery')",
            name=op.f("ck_audit_logs_target_kind_vocabulary"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )

    op.create_index(
        "ix_audit_logs_actor_recorded",
        "audit_logs",
        ["actor_kind", "actor_id", "recorded_at"],
        unique=False,
    )

    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"], unique=False)

    op.create_index(
        "ix_audit_logs_target_recorded",
        "audit_logs",
        ["target_kind", "target_id", "recorded_at"],
        unique=False,
    )

    op.create_table(
        "email_deliveries",
        sa.Column("deduplication_key", sa.UUID(), nullable=False),
        sa.Column("template_code", sa.String(length=32), nullable=False),
        sa.Column("recipient_address", sa.String(length=320), nullable=False),
        sa.Column("subject_kind", sa.String(length=24), nullable=False),
        sa.Column("subject_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_message_id", sa.String(length=255), nullable=True),
        sa.Column("result_code", sa.String(length=64), nullable=True),
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
            "result_code IS NULL OR result_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name=op.f("ck_email_deliveries_result_code_format"),
        ),
        sa.CheckConstraint(
            "state <> 'sent' OR sent_at IS NOT NULL",
            name=op.f("ck_email_deliveries_sent_state_timestamp"),
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'sending', 'sent', 'failed', 'cancelled')",
            name=op.f("ck_email_deliveries_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "subject_kind IN ('account_request', 'user', 'admin')",
            name=op.f("ck_email_deliveries_subject_kind_vocabulary"),
        ),
        sa.CheckConstraint(
            "template_code IN ('account_request_review', 'user_activation', 'password_reset', 'request_rejected')",
            name=op.f("ck_email_deliveries_template_code_vocabulary"),
        ),
        sa.CheckConstraint(
            "attempt_count BETWEEN 0 AND 100", name=op.f("ck_email_deliveries_attempt_count_range")
        ),
        sa.CheckConstraint(
            "length(recipient_address) BETWEEN 3 AND 320",
            name=op.f("ck_email_deliveries_recipient_address_length"),
        ),
        sa.CheckConstraint(
            "provider_message_id IS NULL OR length(provider_message_id) BETWEEN 1 AND 255",
            name=op.f("ck_email_deliveries_provider_message_id_length"),
        ),
        sa.CheckConstraint(
            "sent_at IS NULL OR sent_at >= available_at",
            name=op.f("ck_email_deliveries_sent_after_available"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_deliveries")),
        sa.UniqueConstraint("deduplication_key", name="uq_email_deliveries_deduplication_key"),
    )

    op.create_index(
        "ix_email_deliveries_state_available",
        "email_deliveries",
        ["state", "available_at"],
        unique=False,
    )

    op.create_table(
        "server_health",
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("agent_version", sa.String(length=32), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name=op.f("ck_server_health_error_code_format"),
        ),
        sa.CheckConstraint(
            "source IN ('agent', 'api')", name=op.f("ck_server_health_source_vocabulary")
        ),
        sa.CheckConstraint(
            "state IN ('healthy', 'degraded', 'unreachable', 'unknown')",
            name=op.f("ck_server_health_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "agent_version IS NULL OR length(agent_version) BETWEEN 1 AND 32",
            name=op.f("ck_server_health_agent_version_length"),
        ),
        sa.CheckConstraint(
            "latency_ms IS NULL OR latency_ms BETWEEN 0 AND 600000",
            name=op.f("ck_server_health_latency_ms_range"),
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_server_health_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_server_health")),
        sa.UniqueConstraint(
            "vpn_server_id", "observed_at", name="uq_server_health_server_observed"
        ),
    )

    op.create_index(
        "ix_server_health_server_observed",
        "server_health",
        ["vpn_server_id", "observed_at"],
        unique=False,
    )

    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value_type", sa.String(length=16), nullable=False),
        sa.Column("integer_value", sa.Integer(), nullable=True),
        sa.Column("boolean_value", sa.Boolean(), nullable=True),
        sa.Column("updated_by_admin_id", sa.UUID(), nullable=True),
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
            "(key IN ('default_device_limit', 'default_assignment_ttl_days', 'account_request_retention_days', 'audit_retention_days', 'auth_log_retention_days', 'email_retention_days') AND value_type = 'integer') OR (key IN ('account_requests_enabled') AND value_type = 'boolean')",
            name=op.f("ck_settings_key_value_type_pair"),
        ),
        sa.CheckConstraint(
            "(value_type = 'integer' AND integer_value IS NOT NULL AND boolean_value IS NULL) OR (value_type = 'boolean' AND integer_value IS NULL AND boolean_value IS NOT NULL)",
            name=op.f("ck_settings_typed_value_shape"),
        ),
        sa.CheckConstraint(
            "key IN ('default_device_limit', 'default_assignment_ttl_days', 'account_request_retention_days', 'audit_retention_days', 'auth_log_retention_days', 'email_retention_days', 'account_requests_enabled')",
            name=op.f("ck_settings_key_allowlist"),
        ),
        sa.CheckConstraint(
            "value_type IN ('integer', 'boolean')", name=op.f("ck_settings_value_type_vocabulary")
        ),
        sa.CheckConstraint(
            "integer_value IS NULL OR integer_value BETWEEN 1 AND 3650",
            name=op.f("ck_settings_integer_value_range"),
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_admin_id"],
            ["admin_users.id"],
            name=op.f("fk_settings_updated_by_admin_id_admin_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_settings")),
        sa.UniqueConstraint("key", name="uq_settings_key"),
    )

    op.execute("REVOKE INSERT, UPDATE, DELETE ON TABLE alembic_version FROM nebula_app_runtime")

    op.execute("ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY")

    op.execute("REVOKE UPDATE, DELETE ON TABLE audit_logs FROM nebula_app_runtime")

    op.execute(
        "CREATE POLICY audit_logs_runtime_select ON audit_logs FOR SELECT TO nebula_app_runtime USING (true)"
    )

    op.execute(
        "CREATE POLICY audit_logs_runtime_insert ON audit_logs FOR INSERT TO nebula_app_runtime WITH CHECK (true)"
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_table("server_health")
    op.drop_table("email_deliveries")
    op.drop_table("audit_logs")
    op.drop_table("reconciliation_records")
    op.drop_table("agent_operations")
