"""Agent orchestration, audit, delivery, health, and safe settings records."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from nebula_api.models.types import OperationState, values


def _sql_vocabulary(items: tuple[str, ...]) -> str:
    """Render a trusted closed vocabulary for a SQL CHECK expression."""

    return ", ".join(f"'{item}'" for item in items)


OPERATION_KINDS = (
    "provision_device",
    "revoke_device",
    "enable_device",
    "disable_device",
    "health",
    "reconcile",
)
PROVISIONING_TARGET_KINDS = (
    "device_credential",
    "wireguard_peer",
    "xray_client",
    "server_capability",
    "vpn_server",
)
RECONCILIATION_OUTCOMES = (
    "in_sync",
    "drift_detected",
    "repair_requested",
    "repair_succeeded",
    "repair_failed",
    "ambiguous",
)
AUDIT_ACTOR_KINDS = ("user", "admin", "system", "worker", "agent", "bootstrap")
AUDIT_TARGET_KINDS = (
    "user",
    "admin",
    "device",
    "account_request",
    "protocol_profile",
    "permission",
    "vpn_server",
    "server_capability",
    "assignment",
    "device_credential",
    "wireguard_peer",
    "xray_client",
    "agent_operation",
    "setting",
    "email_delivery",
)
AUDIT_EVENT_CODES = (
    "admin_seeded",
    "identity_state_changed",
    "device_state_changed",
    "account_request_changed",
    "profile_changed",
    "permission_changed",
    "server_changed",
    "capability_changed",
    "assignment_changed",
    "credential_changed",
    "peer_changed",
    "operation_changed",
    "setting_changed",
    "email_delivery_changed",
)
AUDIT_OUTCOMES = ("succeeded", "failed", "denied")
EMAIL_TEMPLATE_CODES = (
    "account_request_review",
    "user_activation",
    "password_reset",
    "request_rejected",
)
EMAIL_STATES = ("pending", "sending", "sent", "failed", "cancelled")
EMAIL_SUBJECT_KINDS = ("account_request", "user", "admin")
HEALTH_STATES = ("healthy", "degraded", "unreachable", "unknown")
HEALTH_SOURCES = ("agent", "api")
SETTING_INTEGER_KEYS = (
    "default_device_limit",
    "default_assignment_ttl_days",
    "account_request_retention_days",
    "audit_retention_days",
    "auth_log_retention_days",
    "email_retention_days",
)
SETTING_BOOLEAN_KEYS = ("account_requests_enabled",)
SETTING_KEYS = SETTING_INTEGER_KEYS + SETTING_BOOLEAN_KEYS
SETTING_VALUE_TYPES = ("integer", "boolean")


class AgentOperation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Replay-resistant typed request sent to one allowlisted agent operation."""

    __tablename__ = "agent_operations"
    __table_args__ = (
        CheckConstraint(
            f"operation_kind IN ({_sql_vocabulary(OPERATION_KINDS)})",
            name="operation_kind_vocabulary",
        ),
        CheckConstraint(
            f"target_kind IN ({_sql_vocabulary(PROVISIONING_TARGET_KINDS)})",
            name="target_kind_vocabulary",
        ),
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(OperationState))})",
            name="state_vocabulary",
        ),
        CheckConstraint("desired_generation >= 0", name="desired_generation_nonnegative"),
        CheckConstraint("attempt_count BETWEEN 0 AND 100", name="attempt_count_range"),
        CheckConstraint(
            "request_fingerprint ~ '^[0-9a-f]{64}$'",
            name="request_fingerprint_format",
        ),
        CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name="error_code_format",
        ),
        CheckConstraint(
            "started_at IS NULL OR started_at >= requested_at",
            name="start_after_request",
        ),
        CheckConstraint(
            "finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at",
            name="finish_after_start",
        ),
        CheckConstraint(
            "state NOT IN ('succeeded', 'failed', 'cancelled') OR finished_at IS NOT NULL",
            name="terminal_state_finished",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_agent_operations_idempotency_key",
        ),
        Index(
            "uq_agent_operations_inflight_target",
            "vpn_server_id",
            "target_kind",
            "target_id",
            unique=True,
            postgresql_where=text("state IN ('pending', 'running')"),
        ),
        Index("ix_agent_operations_server_state", "vpn_server_id", "state"),
    )

    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    idempotency_key: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    correlation_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    operation_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=OperationState.PENDING.value,
        server_default=OperationState.PENDING.value,
    )
    desired_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))

    def __repr__(self) -> str:
        return (
            "AgentOperation("
            f"id={self.id!r}, server_id={self.vpn_server_id!r}, "
            f"kind={self.operation_kind!r}, state={self.state!r})"
        )


class ReconciliationRecord(UUIDPrimaryKeyMixin, Base):
    """Immutable comparison of desired and observed runtime generations."""

    __tablename__ = "reconciliation_records"
    __table_args__ = (
        CheckConstraint(
            f"target_kind IN ({_sql_vocabulary(PROVISIONING_TARGET_KINDS)})",
            name="target_kind_vocabulary",
        ),
        CheckConstraint(
            f"outcome IN ({_sql_vocabulary(RECONCILIATION_OUTCOMES)})",
            name="outcome_vocabulary",
        ),
        CheckConstraint("desired_generation >= 0", name="desired_generation_nonnegative"),
        CheckConstraint(
            "observed_generation IS NULL OR observed_generation >= 0",
            name="observed_generation_nonnegative",
        ),
        CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name="error_code_format",
        ),
        UniqueConstraint(
            "vpn_server_id",
            "target_kind",
            "target_id",
            "checked_at",
            name="uq_reconciliation_records_target_check",
        ),
        Index(
            "ix_reconciliation_records_target_checked",
            "target_kind",
            "target_id",
            "checked_at",
        ),
    )

    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    agent_operation_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("agent_operations.id", ondelete="RESTRICT"),
    )
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    desired_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_generation: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    error_code: Mapped[str | None] = mapped_column(String(64))

    def __repr__(self) -> str:
        return (
            "ReconciliationRecord("
            f"id={self.id!r}, server_id={self.vpn_server_id!r}, "
            f"target_kind={self.target_kind!r}, outcome={self.outcome!r})"
        )


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Append-oriented, allowlisted security event without payload snapshots."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint(
            f"actor_kind IN ({_sql_vocabulary(AUDIT_ACTOR_KINDS)})",
            name="actor_kind_vocabulary",
        ),
        CheckConstraint(
            f"target_kind IN ({_sql_vocabulary(AUDIT_TARGET_KINDS)})",
            name="target_kind_vocabulary",
        ),
        CheckConstraint(
            f"event_code IN ({_sql_vocabulary(AUDIT_EVENT_CODES)})",
            name="event_code_vocabulary",
        ),
        CheckConstraint(
            f"outcome IN ({_sql_vocabulary(AUDIT_OUTCOMES)})",
            name="outcome_vocabulary",
        ),
        CheckConstraint(
            "(actor_kind IN ('system', 'worker', 'bootstrap') AND actor_id IS NULL) OR "
            "(actor_kind IN ('user', 'admin', 'agent') AND actor_id IS NOT NULL)",
            name="actor_identity_shape",
        ),
        CheckConstraint(
            "reason_code IS NULL OR reason_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name="reason_code_format",
        ),
        Index("ix_audit_logs_actor_recorded", "actor_kind", "actor_id", "recorded_at"),
        Index("ix_audit_logs_target_recorded", "target_kind", "target_id", "recorded_at"),
        Index("ix_audit_logs_request_id", "request_id"),
    )

    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(PostgreSQLUUID(as_uuid=True))
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    event_code: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    request_id: Mapped[UUID | None] = mapped_column(PostgreSQLUUID(as_uuid=True))
    correlation_id: Mapped[UUID | None] = mapped_column(PostgreSQLUUID(as_uuid=True))
    reason_code: Mapped[str | None] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return (
            "AuditLog("
            f"id={self.id!r}, actor_kind={self.actor_kind!r}, "
            f"event_code={self.event_code!r}, outcome={self.outcome!r})"
        )


class EmailDelivery(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Redacted durable email intent; no body or one-time link is retained."""

    __tablename__ = "email_deliveries"
    __table_args__ = (
        CheckConstraint(
            f"template_code IN ({_sql_vocabulary(EMAIL_TEMPLATE_CODES)})",
            name="template_code_vocabulary",
        ),
        CheckConstraint(
            f"state IN ({_sql_vocabulary(EMAIL_STATES)})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            f"subject_kind IN ({_sql_vocabulary(EMAIL_SUBJECT_KINDS)})",
            name="subject_kind_vocabulary",
        ),
        CheckConstraint("attempt_count BETWEEN 0 AND 100", name="attempt_count_range"),
        CheckConstraint(
            "length(recipient_address) BETWEEN 3 AND 320",
            name="recipient_address_length",
        ),
        CheckConstraint(
            "provider_message_id IS NULL OR length(provider_message_id) BETWEEN 1 AND 255",
            name="provider_message_id_length",
        ),
        CheckConstraint(
            "result_code IS NULL OR result_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name="result_code_format",
        ),
        CheckConstraint(
            "sent_at IS NULL OR sent_at >= available_at",
            name="sent_after_available",
        ),
        CheckConstraint(
            "state <> 'sent' OR sent_at IS NOT NULL",
            name="sent_state_timestamp",
        ),
        UniqueConstraint(
            "deduplication_key",
            name="uq_email_deliveries_deduplication_key",
        ),
        Index("ix_email_deliveries_state_available", "state", "available_at"),
    )

    deduplication_key: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    template_code: Mapped[str] = mapped_column(String(32), nullable=False)
    recipient_address: Mapped[str] = mapped_column(String(320), nullable=False)
    subject_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    subject_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    leased_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provider_message_id: Mapped[str | None] = mapped_column(String(255))
    result_code: Mapped[str | None] = mapped_column(String(64))

    def __repr__(self) -> str:
        return (
            "EmailDelivery("
            f"id={self.id!r}, template_code={self.template_code!r}, state={self.state!r})"
        )


class ServerHealth(UUIDPrimaryKeyMixin, Base):
    """Coarse immutable server-health sample without user traffic metadata."""

    __tablename__ = "server_health"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({_sql_vocabulary(HEALTH_STATES)})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            f"source IN ({_sql_vocabulary(HEALTH_SOURCES)})",
            name="source_vocabulary",
        ),
        CheckConstraint(
            "latency_ms IS NULL OR latency_ms BETWEEN 0 AND 600000",
            name="latency_ms_range",
        ),
        CheckConstraint(
            "agent_version IS NULL OR length(agent_version) BETWEEN 1 AND 32",
            name="agent_version_length",
        ),
        CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'",
            name="error_code_format",
        ),
        UniqueConstraint(
            "vpn_server_id",
            "observed_at",
            name="uq_server_health_server_observed",
        ),
        Index("ix_server_health_server_observed", "vpn_server_id", "observed_at"),
    )

    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    error_code: Mapped[str | None] = mapped_column(String(64))

    def __repr__(self) -> str:
        return (
            f"ServerHealth(id={self.id!r}, server_id={self.vpn_server_id!r}, state={self.state!r})"
        )


class Setting(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Strict allowlist of non-secret, typed global operational settings."""

    __tablename__ = "settings"
    __table_args__ = (
        CheckConstraint(
            f"key IN ({_sql_vocabulary(SETTING_KEYS)})",
            name="key_allowlist",
        ),
        CheckConstraint(
            f"value_type IN ({_sql_vocabulary(SETTING_VALUE_TYPES)})",
            name="value_type_vocabulary",
        ),
        CheckConstraint(
            "(value_type = 'integer' AND integer_value IS NOT NULL AND "
            "boolean_value IS NULL) OR "
            "(value_type = 'boolean' AND integer_value IS NULL AND "
            "boolean_value IS NOT NULL)",
            name="typed_value_shape",
        ),
        CheckConstraint(
            f"(key IN ({_sql_vocabulary(SETTING_INTEGER_KEYS)}) AND "
            "value_type = 'integer') OR "
            f"(key IN ({_sql_vocabulary(SETTING_BOOLEAN_KEYS)}) AND "
            "value_type = 'boolean')",
            name="key_value_type_pair",
        ),
        CheckConstraint(
            "integer_value IS NULL OR integer_value BETWEEN 1 AND 3650",
            name="integer_value_range",
        ),
        UniqueConstraint("key", name="uq_settings_key"),
    )

    key: Mapped[str] = mapped_column(String(64), nullable=False)
    value_type: Mapped[str] = mapped_column(String(16), nullable=False)
    integer_value: Mapped[int | None] = mapped_column(Integer)
    boolean_value: Mapped[bool | None] = mapped_column(Boolean)
    updated_by_admin_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="RESTRICT"),
    )

    def __repr__(self) -> str:
        return f"Setting(id={self.id!r}, key={self.key!r}, value_type={self.value_type!r})"
