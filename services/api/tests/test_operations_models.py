from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from sqlalchemy import CheckConstraint, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.schema import CreateTable

from nebula_api.models.operations import (
    AgentOperation,
    AuditLog,
    EmailDelivery,
    ReconciliationRecord,
    ServerHealth,
    Setting,
)

OPERATION_MODELS = (
    AgentOperation,
    ReconciliationRecord,
    AuditLog,
    EmailDelivery,
    ServerHealth,
    Setting,
)


def _check_sql(model: type[object]) -> str:
    constraints = (
        constraint
        for constraint in model.__table__.constraints  # type: ignore[attr-defined]
        if isinstance(constraint, CheckConstraint)
    )
    return " ".join(str(constraint.sqltext) for constraint in constraints)


def test_operation_table_names_and_uuid_boundaries_are_stable() -> None:
    assert {model.__tablename__ for model in OPERATION_MODELS} == {
        "agent_operations",
        "reconciliation_records",
        "audit_logs",
        "email_deliveries",
        "server_health",
        "settings",
    }
    for model in OPERATION_MODELS:
        assert isinstance(model.__table__.c.id.type, PostgreSQLUUID)
        assert not model.__mapper__.relationships


def test_operations_store_only_allowlisted_codes_not_payloads() -> None:
    forbidden_names = {
        "body",
        "content",
        "payload",
        "request_json",
        "response_json",
        "raw_result",
        "command",
        "shell",
        "path",
        "config",
        "private_key",
        "plaintext_token",
    }
    for model in OPERATION_MODELS:
        assert forbidden_names.isdisjoint(model.__table__.c.keys())

    assert "provision_device" in _check_sql(AgentOperation)
    assert "request_fingerprint" in _check_sql(AgentOperation)
    assert "drift_detected" in _check_sql(ReconciliationRecord)
    assert "event_code IN" in _check_sql(AuditLog)


def test_agent_operations_are_idempotent_and_single_flight_per_target() -> None:
    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in cast(Table, AgentOperation.__table__).constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("idempotency_key",) in unique_columns

    inflight = next(
        index
        for index in cast(Table, AgentOperation.__table__).indexes
        if index.name == "uq_agent_operations_inflight_target"
    )
    assert inflight.unique
    assert [column.name for column in inflight.columns] == [
        "vpn_server_id",
        "target_kind",
        "target_id",
    ]
    assert "pending" in str(inflight.dialect_options["postgresql"]["where"])


def test_audit_and_health_rows_are_immutable_samples() -> None:
    assert "updated_at" not in AuditLog.__table__.c
    assert "updated_at" not in ReconciliationRecord.__table__.c
    assert "updated_at" not in ServerHealth.__table__.c

    audit_checks = _check_sql(AuditLog)
    assert "actor_kind IN" in audit_checks
    assert "outcome IN" in audit_checks
    assert "reason_code" in audit_checks


def test_email_delivery_has_no_message_body_or_link_and_is_deduplicated() -> None:
    columns = set(EmailDelivery.__table__.c.keys())
    assert {"body", "html", "text", "link", "token"}.isdisjoint(columns)
    assert {"template_code", "recipient_address", "deduplication_key"} <= columns
    assert "user_activation" in _check_sql(EmailDelivery)

    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in cast(Table, EmailDelivery.__table__).constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("deduplication_key",) in unique_columns


def test_settings_are_typed_and_strictly_allowlisted() -> None:
    columns = set(Setting.__table__.c.keys())
    assert {"integer_value", "boolean_value"} <= columns
    assert {"text_value", "json_value", "secret_value"}.isdisjoint(columns)

    checks = _check_sql(Setting)
    assert "default_device_limit" in checks
    assert "account_requests_enabled" in checks
    assert "integer_value IS NOT NULL" in checks
    assert "boolean_value IS NOT NULL" in checks
    assert any(
        constraint.name == "ck_settings_key_value_type_pair"
        for constraint in cast(Table, Setting.__table__).constraints
        if isinstance(constraint, CheckConstraint)
    )


def test_every_operations_foreign_key_is_restrictive() -> None:
    for model in OPERATION_MODELS:
        for foreign_key in model.__table__.foreign_keys:
            assert foreign_key.ondelete == "RESTRICT"


def test_operations_ddl_compiles_for_postgresql() -> None:
    dialect = PGDialect()  # type: ignore[no-untyped-call]
    for model in OPERATION_MODELS:
        ddl = str(CreateTable(cast(Table, model.__table__)).compile(dialect=dialect)).lower()
        assert "uuid" in ddl
        assert "timestamp with time zone" in ddl
        assert "check" in ddl


def test_operational_representations_exclude_sensitive_values_and_pii() -> None:
    identifier = uuid4()
    now = datetime.now(UTC)
    instances = (
        AgentOperation(
            id=identifier,
            vpn_server_id=identifier,
            operation_kind="provision_device",
            state="pending",
            request_fingerprint="f" * 64,
        ),
        ReconciliationRecord(
            id=identifier,
            vpn_server_id=identifier,
            target_kind="wireguard_peer",
            outcome="in_sync",
        ),
        AuditLog(
            id=identifier,
            actor_kind="system",
            event_code="peer_changed",
            outcome="succeeded",
        ),
        EmailDelivery(
            id=identifier,
            template_code="user_activation",
            recipient_address="sensitive.person@example.com",
            state="pending",
        ),
        ServerHealth(id=identifier, vpn_server_id=identifier, state="healthy"),
        Setting(
            id=identifier,
            key="default_device_limit",
            value_type="integer",
            integer_value=5,
        ),
    )

    rendered = " ".join(repr(instance) for instance in instances)
    assert "sensitive.person@example.com" not in rendered
    assert "f" * 64 not in rendered
    assert "integer_value" not in rendered
    assert now.isoformat() not in rendered
