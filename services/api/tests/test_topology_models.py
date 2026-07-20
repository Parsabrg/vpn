from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from sqlalchemy import CheckConstraint, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import CIDR, INET
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.schema import CreateTable

from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ProtocolProfilePlatform,
    ServerProtocolCapability,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)

TOPOLOGY_MODELS = (
    Protocol,
    ProtocolProfile,
    ProtocolProfilePlatform,
    UserProtocolPermission,
    VPNServer,
    ServerProtocolCapability,
    UserServerAssignment,
)


def _check_sql(model: type[object]) -> str:
    constraints = (
        constraint
        for constraint in model.__table__.constraints  # type: ignore[attr-defined]
        if isinstance(constraint, CheckConstraint)
    )
    return " ".join(str(constraint.sqltext) for constraint in constraints)


def test_topology_tables_and_postgresql_types_are_stable() -> None:
    assert {model.__tablename__ for model in TOPOLOGY_MODELS} == {
        "protocols",
        "protocol_profiles",
        "protocol_profile_platforms",
        "user_protocol_permissions",
        "vpn_servers",
        "server_protocol_capabilities",
        "user_server_assignments",
    }
    assert isinstance(VPNServer.__table__.c.wireguard_client_pool.type, CIDR)
    assert isinstance(VPNServer.__table__.c.wireguard_gateway_address.type, INET)

    for model in TOPOLOGY_MODELS:
        assert isinstance(model.__table__.c.id.type, PostgreSQLUUID)
        assert not model.__mapper__.relationships


def test_topology_foreign_keys_are_restrictive() -> None:
    for model in TOPOLOGY_MODELS:
        for foreign_key in model.__table__.foreign_keys:
            assert foreign_key.ondelete == "RESTRICT"


def test_profile_registry_is_closed_and_profile_grants_are_composite_unique() -> None:
    protocol_checks = _check_sql(Protocol)
    profile_checks = _check_sql(ProtocolProfile)

    assert "wireguard" in protocol_checks
    assert "native_wireguard" in protocol_checks
    assert "xray" in protocol_checks
    assert "transport IN" in profile_checks
    assert "transport_security IN" in profile_checks
    assert "template_key" in profile_checks

    permission_uniques = {
        tuple(column.name for column in constraint.columns)
        for constraint in cast(Table, UserProtocolPermission.__table__).constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("user_id", "protocol_profile_id") in permission_uniques


def test_profile_tuple_and_active_assignment_indexes_are_explicit() -> None:
    tuple_constraint = next(
        constraint
        for constraint in cast(Table, ProtocolProfile.__table__).constraints
        if isinstance(constraint, UniqueConstraint)
        and constraint.name == "uq_protocol_profiles_reviewed_tuple"
    )
    assert tuple_constraint.dialect_options["postgresql"]["nulls_not_distinct"] is True

    active_index = next(
        index
        for index in cast(Table, UserServerAssignment.__table__).indexes
        if index.name == "uq_user_server_assignments_active_user_server"
    )
    assert active_index.unique
    assert [column.name for column in active_index.columns] == ["user_id", "vpn_server_id"]
    assert "state = 'active'" in str(active_index.dialect_options["postgresql"]["where"])


def test_topology_ddl_compiles_for_postgresql() -> None:
    dialect = PGDialect()  # type: ignore[no-untyped-call]
    profile_table = cast(Table, ProtocolProfile.__table__)
    server_table = cast(Table, VPNServer.__table__)
    ddl = str(CreateTable(profile_table).compile(dialect=dialect)).lower()
    server_ddl = str(CreateTable(server_table).compile(dialect=dialect)).lower()

    assert "nulls not distinct" in ddl
    assert "check" in ddl
    assert "cidr" in server_ddl
    assert "inet" in server_ddl


def test_topology_representations_use_only_non_sensitive_identity() -> None:
    identifier = uuid4()
    now = datetime.now(UTC)
    instances = (
        Protocol(id=identifier, code="wireguard", engine="native_wireguard"),
        ProtocolProfile(
            id=identifier,
            code="wireguard",
            version=1,
            state="implemented",
        ),
        ProtocolProfilePlatform(id=identifier, protocol_profile_id=identifier, platform="android"),
        UserProtocolPermission(
            id=identifier,
            user_id=identifier,
            protocol_profile_id=identifier,
            state="enabled",
            granted_at=now,
        ),
        VPNServer(id=identifier, code="primary", state="active"),
        ServerProtocolCapability(
            id=identifier,
            vpn_server_id=identifier,
            protocol_profile_id=identifier,
            state="enabled",
        ),
        UserServerAssignment(
            id=identifier,
            user_id=identifier,
            vpn_server_id=identifier,
            state="active",
            assigned_at=now,
        ),
    )

    for instance in instances:
        rendered = repr(instance)
        assert instance.__class__.__name__ in rendered
        assert "secret" not in rendered.lower()


def test_profiles_are_versioned_and_capabilities_require_service_validation() -> None:
    profile_table = cast(Table, ProtocolProfile.__table__)
    assert not profile_table.c.version.nullable
    assert "version >= 1" in _check_sql(ProtocolProfile)

    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in profile_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("code", "version") in unique_columns
    assert ("code",) not in unique_columns
    assert ServerProtocolCapability.IMPLEMENTABLE_PROFILE_STATE == "implemented"
    assert "implemented" not in _check_sql(ServerProtocolCapability)
