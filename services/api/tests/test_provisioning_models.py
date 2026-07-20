from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    Table,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.schema import CreateTable

from nebula_api.models.provisioning import (
    DeviceProtocolCredential,
    WireGuardPeer,
    XrayClient,
)

PROVISIONING_MODELS = (DeviceProtocolCredential, WireGuardPeer, XrayClient)


def _check_sql(model: type[object]) -> str:
    constraints = (
        constraint
        for constraint in model.__table__.constraints  # type: ignore[attr-defined]
        if isinstance(constraint, CheckConstraint)
    )
    return " ".join(str(constraint.sqltext) for constraint in constraints)


def test_provisioning_tables_have_no_raw_secret_or_configuration_columns() -> None:
    assert {model.__tablename__ for model in PROVISIONING_MODELS} == {
        "device_protocol_credentials",
        "wireguard_peers",
        "xray_clients",
    }

    forbidden_fragments = (
        "private_key",
        "plaintext",
        "raw_",
        "json",
        "shell",
        "command",
        "binary_path",
        "config",
    )
    for model in PROVISIONING_MODELS:
        column_names = {column.name for column in model.__table__.columns}
        assert not any(
            fragment in column_name
            for column_name in column_names
            for fragment in forbidden_fragments
        )
        assert not model.__mapper__.relationships


def test_encrypted_credential_tuple_is_complete_and_wireguard_forbids_it() -> None:
    columns = DeviceProtocolCredential.__table__.c
    assert columns.ciphertext.nullable
    assert columns.nonce.nullable
    assert columns.key_version.nullable

    checks = _check_sql(DeviceProtocolCredential)
    assert "ciphertext IS NULL AND nonce IS NULL AND key_version IS NULL" in checks
    assert "ciphertext IS NOT NULL AND nonce IS NOT NULL AND key_version IS NOT NULL" in checks
    assert "kind <> 'wireguard_public'" in checks
    assert "active" in checks and "xray_bearer" in checks


def test_runtime_rows_use_identity_and_kind_restricted_composite_foreign_keys() -> None:
    for model, expected_kind in (
        (WireGuardPeer, "wireguard_public"),
        (XrayClient, "xray_bearer"),
    ):
        composite = next(
            constraint
            for constraint in cast(Table, model.__table__).constraints
            if isinstance(constraint, ForeignKeyConstraint) and len(constraint.column_keys) == 5
        )
        assert composite.column_keys == [
            "credential_id",
            "credential_kind",
            "device_id",
            "protocol_profile_id",
            "vpn_server_id",
        ]
        assert composite.ondelete == "RESTRICT"
        assert expected_kind in _check_sql(model)


def test_wireguard_address_and_uniqueness_are_database_enforced() -> None:
    assert isinstance(WireGuardPeer.__table__.c.assigned_address.type, INET)
    assert "masklen(assigned_address) IN (32, 128)" in _check_sql(WireGuardPeer)

    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in cast(Table, WireGuardPeer.__table__).constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("vpn_server_id", "assigned_address") in unique_columns
    assert ("public_key",) in unique_columns

    active_index = next(
        index
        for index in cast(Table, WireGuardPeer.__table__).indexes
        if index.name == "uq_wireguard_peers_live_device"
    )
    assert active_index.unique
    assert "state IN" in str(active_index.dialect_options["postgresql"]["where"])


def test_every_provisioning_foreign_key_is_restrictive() -> None:
    for model in PROVISIONING_MODELS:
        for foreign_key in model.__table__.foreign_keys:
            assert foreign_key.ondelete == "RESTRICT"


def test_provisioning_ddl_compiles_for_postgresql() -> None:
    dialect = PGDialect()  # type: ignore[no-untyped-call]
    for model in PROVISIONING_MODELS:
        ddl = str(CreateTable(cast(Table, model.__table__)).compile(dialect=dialect)).lower()
        assert "check" in ddl
        assert "on delete restrict" in ddl
    assert (
        "inet"
        in str(CreateTable(cast(Table, WireGuardPeer.__table__)).compile(dialect=dialect)).lower()
    )


def test_secret_bearing_models_have_redacted_representations() -> None:
    identifier = uuid4()
    now = datetime.now(UTC)
    marker = b"do-not-render-ciphertext"
    credential = DeviceProtocolCredential(
        id=identifier,
        device_id=identifier,
        protocol_profile_id=identifier,
        vpn_server_id=identifier,
        kind="xray_bearer",
        state="active",
        generation=1,
        ciphertext=marker,
        nonce=b"nonce-marker",
        key_version="key-marker",
        issued_at=now,
    )
    wireguard = WireGuardPeer(
        id=identifier,
        device_id=identifier,
        vpn_server_id=identifier,
        state="active",
        public_key="public-key-marker",
        assigned_address="10.77.0.2",
    )
    xray = XrayClient(
        id=identifier,
        device_id=identifier,
        vpn_server_id=identifier,
        state="active",
        opaque_label="opaque-marker-value",
    )

    rendered = " ".join((repr(credential), repr(wireguard), repr(xray)))
    assert marker.decode() not in rendered
    assert "nonce-marker" not in rendered
    assert "key-marker" not in rendered
    assert "public-key-marker" not in rendered
    assert "opaque-marker-value" not in rendered
