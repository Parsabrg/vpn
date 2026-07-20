"""Protocol-neutral credential intent and runtime peer/client records."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from nebula_api.models.types import ProvisioningState, values


def _sql_vocabulary(items: tuple[str, ...]) -> str:
    """Render a trusted closed vocabulary for a SQL CHECK expression."""

    return ", ".join(f"'{item}'" for item in items)


CREDENTIAL_KINDS = ("wireguard_public", "xray_bearer")


class DeviceProtocolCredential(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Credential lifecycle metadata with optional envelope-encrypted Xray material."""

    __tablename__ = "device_protocol_credentials"
    __table_args__ = (
        CheckConstraint(
            f"kind IN ({_sql_vocabulary(CREDENTIAL_KINDS)})",
            name="kind_vocabulary",
        ),
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(ProvisioningState))})",
            name="state_vocabulary",
        ),
        CheckConstraint("generation >= 1", name="generation_positive"),
        CheckConstraint(
            "(ciphertext IS NULL AND nonce IS NULL AND key_version IS NULL) OR "
            "(ciphertext IS NOT NULL AND nonce IS NOT NULL AND key_version IS NOT NULL)",
            name="aead_tuple_complete",
        ),
        CheckConstraint(
            "kind <> 'wireguard_public' OR "
            "(ciphertext IS NULL AND nonce IS NULL AND key_version IS NULL)",
            name="wireguard_has_no_encrypted_secret",
        ),
        CheckConstraint(
            "kind <> 'xray_bearer' OR state NOT IN ('active', 'revoking') OR "
            "ciphertext IS NOT NULL",
            name="active_xray_has_encrypted_secret",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > issued_at",
            name="expiry_after_issue",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= issued_at",
            name="revocation_after_issue",
        ),
        CheckConstraint(
            "state <> 'revoked' OR revoked_at IS NOT NULL",
            name="revoked_state_timestamp",
        ),
        UniqueConstraint(
            "id",
            "kind",
            "device_id",
            "protocol_profile_id",
            "vpn_server_id",
            name="uq_device_protocol_credentials_runtime_identity",
        ),
        Index(
            "uq_device_protocol_credentials_live_device_profile",
            "device_id",
            "protocol_profile_id",
            unique=True,
            postgresql_where=text("state IN ('requested', 'applying', 'active', 'revoking')"),
        ),
        Index(
            "ix_device_protocol_credentials_server_state",
            "vpn_server_id",
            "state",
        ),
    )

    device_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
    )
    protocol_profile_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("protocol_profiles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ProvisioningState.REQUESTED.value,
        server_default=ProvisioningState.REQUESTED.value,
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_version: Mapped[str | None] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return (
            "DeviceProtocolCredential("
            f"id={self.id!r}, device_id={self.device_id!r}, kind={self.kind!r}, "
            f"state={self.state!r}, generation={self.generation!r})"
        )


class WireGuardPeer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """WireGuard public peer state; client and server private keys are never stored."""

    __tablename__ = "wireguard_peers"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "credential_id",
                "credential_kind",
                "device_id",
                "protocol_profile_id",
                "vpn_server_id",
            ],
            [
                "device_protocol_credentials.id",
                "device_protocol_credentials.kind",
                "device_protocol_credentials.device_id",
                "device_protocol_credentials.protocol_profile_id",
                "device_protocol_credentials.vpn_server_id",
            ],
            ondelete="RESTRICT",
            name="fk_wireguard_peers_credential_identity",
        ),
        CheckConstraint(
            "credential_kind = 'wireguard_public'",
            name="credential_kind_wireguard",
        ),
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(ProvisioningState))})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            "public_key ~ '^[A-Za-z0-9+/]{43}=$' AND "
            "public_key <> 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
            name="public_key_canonical",
        ),
        CheckConstraint(
            "masklen(assigned_address) IN (32, 128)",
            name="assigned_address_is_host",
        ),
        CheckConstraint("applied_generation >= 0", name="applied_generation_nonnegative"),
        CheckConstraint(
            "revoked_at IS NULL OR applied_at IS NULL OR revoked_at >= applied_at",
            name="revocation_after_apply",
        ),
        UniqueConstraint(
            "credential_id",
            name="uq_wireguard_peers_credential",
        ),
        UniqueConstraint("public_key", name="uq_wireguard_peers_public_key"),
        UniqueConstraint(
            "vpn_server_id",
            "assigned_address",
            name="uq_wireguard_peers_server_address",
        ),
        Index(
            "uq_wireguard_peers_live_device",
            "device_id",
            unique=True,
            postgresql_where=text("state IN ('requested', 'applying', 'active', 'revoking')"),
        ),
        Index("ix_wireguard_peers_server_state", "vpn_server_id", "state"),
    )

    credential_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    credential_kind: Mapped[str] = mapped_column(
        String(24), nullable=False, default="wireguard_public", server_default="wireguard_public"
    )
    device_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
    )
    protocol_profile_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("protocol_profiles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    public_key: Mapped[str] = mapped_column(String(44), nullable=False)
    assigned_address: Mapped[str] = mapped_column(INET, nullable=False)
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ProvisioningState.REQUESTED.value,
        server_default=ProvisioningState.REQUESTED.value,
    )
    applied_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return (
            "WireGuardPeer("
            f"id={self.id!r}, device_id={self.device_id!r}, "
            f"server_id={self.vpn_server_id!r}, state={self.state!r})"
        )


class XrayClient(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Opaque runtime label linked to an encrypted per-device/profile credential."""

    __tablename__ = "xray_clients"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "credential_id",
                "credential_kind",
                "device_id",
                "protocol_profile_id",
                "vpn_server_id",
            ],
            [
                "device_protocol_credentials.id",
                "device_protocol_credentials.kind",
                "device_protocol_credentials.device_id",
                "device_protocol_credentials.protocol_profile_id",
                "device_protocol_credentials.vpn_server_id",
            ],
            ondelete="RESTRICT",
            name="fk_xray_clients_credential_identity",
        ),
        CheckConstraint("credential_kind = 'xray_bearer'", name="credential_kind_xray"),
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(ProvisioningState))})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            "opaque_label ~ '^[A-Za-z0-9_-]{16,64}$'",
            name="opaque_label_format",
        ),
        CheckConstraint("applied_generation >= 0", name="applied_generation_nonnegative"),
        CheckConstraint(
            "revoked_at IS NULL OR applied_at IS NULL OR revoked_at >= applied_at",
            name="revocation_after_apply",
        ),
        UniqueConstraint("credential_id", name="uq_xray_clients_credential"),
        UniqueConstraint("opaque_label", name="uq_xray_clients_opaque_label"),
        Index(
            "uq_xray_clients_live_device_profile",
            "device_id",
            "protocol_profile_id",
            unique=True,
            postgresql_where=text("state IN ('requested', 'applying', 'active', 'revoking')"),
        ),
        Index("ix_xray_clients_server_state", "vpn_server_id", "state"),
    )

    credential_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    credential_kind: Mapped[str] = mapped_column(
        String(24), nullable=False, default="xray_bearer", server_default="xray_bearer"
    )
    device_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
    )
    protocol_profile_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("protocol_profiles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    opaque_label: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ProvisioningState.REQUESTED.value,
        server_default=ProvisioningState.REQUESTED.value,
    )
    applied_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return (
            "XrayClient("
            f"id={self.id!r}, device_id={self.device_id!r}, "
            f"server_id={self.vpn_server_id!r}, state={self.state!r})"
        )
