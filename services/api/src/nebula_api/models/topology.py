"""Protocol registry, server topology, and authorization-independent grants."""

from datetime import datetime
from typing import ClassVar
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
    text,
)
from sqlalchemy.dialects.postgresql import CIDR, INET
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from nebula_api.models.types import (
    CapabilityState,
    DevicePlatform,
    LifecycleState,
    ProfileState,
    ProtocolEngine,
    ServerState,
    values,
)


def _sql_vocabulary(items: tuple[str, ...]) -> str:
    """Render a trusted closed vocabulary for a SQL CHECK expression."""

    return ", ".join(f"'{item}'" for item in items)


PROTOCOL_CODES = ("wireguard", "vless", "vmess", "trojan", "shadowsocks", "hysteria2")
TRANSPORT_CODES = ("raw", "xhttp", "mkcp", "grpc", "websocket", "httpupgrade", "hysteria")
TRANSPORT_SECURITY_CODES = ("tls", "reality")
FLOW_CODES = ("xtls_vision",)


class Protocol(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Reviewed user-facing protocol, never an arbitrary runtime primitive."""

    __tablename__ = "protocols"
    __table_args__ = (
        CheckConstraint(
            f"code IN ({_sql_vocabulary(PROTOCOL_CODES)})",
            name="code_vocabulary",
        ),
        CheckConstraint(
            f"engine IN ({_sql_vocabulary(values(ProtocolEngine))})",
            name="engine_vocabulary",
        ),
        CheckConstraint(
            "(code = 'wireguard' AND engine = 'native_wireguard') OR "
            "(code <> 'wireguard' AND engine = 'xray')",
            name="code_engine_pair",
        ),
        CheckConstraint("length(display_name) BETWEEN 1 AND 64", name="display_name_length"),
        UniqueConstraint("code", name="uq_protocols_code"),
    )

    code: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    is_user_selectable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    def __repr__(self) -> str:
        return f"Protocol(id={self.id!r}, code={self.code!r}, engine={self.engine!r})"


class ProtocolProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Versioned, reviewed protocol tuple referencing a trusted template key."""

    __tablename__ = "protocol_profiles"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(ProfileState))})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            f"transport IS NULL OR transport IN ({_sql_vocabulary(TRANSPORT_CODES)})",
            name="transport_vocabulary",
        ),
        CheckConstraint(
            "transport_security IS NULL OR "
            f"transport_security IN ({_sql_vocabulary(TRANSPORT_SECURITY_CODES)})",
            name="transport_security_vocabulary",
        ),
        CheckConstraint(
            f"flow IS NULL OR flow IN ({_sql_vocabulary(FLOW_CODES)})",
            name="flow_vocabulary",
        ),
        CheckConstraint("length(code) BETWEEN 1 AND 64", name="code_length"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint("length(display_name) BETWEEN 1 AND 96", name="display_name_length"),
        CheckConstraint(
            "template_key IS NULL OR template_key ~ '^[a-z0-9][a-z0-9_.-]{0,95}$'",
            name="template_key_format",
        ),
        CheckConstraint(
            "template_version IS NULL OR length(template_version) BETWEEN 1 AND 32",
            name="template_version_length",
        ),
        CheckConstraint(
            "required_port IS NULL OR required_port BETWEEN 1 AND 65535",
            name="required_port_range",
        ),
        UniqueConstraint(
            "code",
            "version",
            name="uq_protocol_profiles_code_version",
        ),
        UniqueConstraint(
            "protocol_id",
            "transport",
            "transport_security",
            "flow",
            "template_key",
            "template_version",
            name="uq_protocol_profiles_reviewed_tuple",
            postgresql_nulls_not_distinct=True,
        ),
    )

    protocol_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("protocols.id", ondelete="RESTRICT"),
        nullable=False,
    )
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    display_name: Mapped[str] = mapped_column(String(96), nullable=False)
    state: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=ProfileState.DRAFT.value,
        server_default=ProfileState.DRAFT.value,
    )
    transport: Mapped[str | None] = mapped_column(String(24))
    transport_security: Mapped[str | None] = mapped_column(String(16))
    flow: Mapped[str | None] = mapped_column(String(24))
    template_key: Mapped[str | None] = mapped_column(String(96))
    template_version: Mapped[str | None] = mapped_column(String(32))
    required_port: Mapped[int | None] = mapped_column(Integer)
    requires_udp: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    is_full_tunnel: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    def __repr__(self) -> str:
        return (
            "ProtocolProfile("
            f"id={self.id!r}, code={self.code!r}, version={self.version!r}, "
            f"state={self.state!r})"
        )


class ProtocolProfilePlatform(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Client-platform compatibility declared for one reviewed profile."""

    __tablename__ = "protocol_profile_platforms"
    __table_args__ = (
        CheckConstraint(
            f"platform IN ({_sql_vocabulary(values(DevicePlatform))})",
            name="platform_vocabulary",
        ),
        CheckConstraint(
            "minimum_client_version IS NULL OR length(minimum_client_version) BETWEEN 1 AND 32",
            name="minimum_client_version_length",
        ),
        UniqueConstraint(
            "protocol_profile_id",
            "platform",
            name="uq_protocol_profile_platforms_profile_platform",
        ),
    )

    protocol_profile_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("protocol_profiles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    platform: Mapped[str] = mapped_column(String(16), nullable=False)
    minimum_client_version: Mapped[str | None] = mapped_column(String(32))
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    def __repr__(self) -> str:
        return (
            "ProtocolProfilePlatform("
            f"id={self.id!r}, profile_id={self.protocol_profile_id!r}, "
            f"platform={self.platform!r})"
        )


class UserProtocolPermission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Profile-level grant; profile access never defaults to allowed."""

    __tablename__ = "user_protocol_permissions"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(CapabilityState))})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > granted_at",
            name="expiry_after_grant",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= granted_at",
            name="revocation_after_grant",
        ),
        CheckConstraint(
            "(state = 'enabled' AND revoked_at IS NULL) OR (state = 'disabled')",
            name="enabled_not_revoked",
        ),
        UniqueConstraint(
            "user_id",
            "protocol_profile_id",
            name="uq_user_protocol_permissions_user_profile",
        ),
    )

    user_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    protocol_profile_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("protocol_profiles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    granted_by_admin_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="RESTRICT"),
    )
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=CapabilityState.DISABLED.value,
        server_default=CapabilityState.DISABLED.value,
    )
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return (
            "UserProtocolPermission("
            f"id={self.id!r}, user_id={self.user_id!r}, "
            f"profile_id={self.protocol_profile_id!r}, state={self.state!r})"
        )


class VPNServer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """VPN host metadata; secret keys and agent credentials never belong here."""

    __tablename__ = "vpn_servers"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(ServerState))})",
            name="state_vocabulary",
        ),
        CheckConstraint("length(code) BETWEEN 1 AND 64", name="code_length"),
        CheckConstraint("length(display_name) BETWEEN 1 AND 96", name="display_name_length"),
        CheckConstraint("agent_port BETWEEN 1 AND 65535", name="agent_port_range"),
        CheckConstraint(
            "length(agent_host) BETWEEN 1 AND 253 AND agent_host !~ '[/:@[:space:]]'",
            name="agent_host_format",
        ),
        CheckConstraint(
            "length(public_host) BETWEEN 1 AND 253 AND public_host !~ '[/:@[:space:]]'",
            name="public_host_format",
        ),
        CheckConstraint(
            "maximum_devices BETWEEN 1 AND 100000",
            name="maximum_devices_range",
        ),
        CheckConstraint(
            "wireguard_gateway_address IS NULL OR "
            "(wireguard_client_pool IS NOT NULL AND "
            "wireguard_gateway_address <<= wireguard_client_pool AND "
            "masklen(wireguard_gateway_address) IN (32, 128))",
            name="gateway_in_pool",
        ),
        UniqueConstraint("code", name="uq_vpn_servers_code"),
        UniqueConstraint(
            "agent_host",
            "agent_port",
            name="uq_vpn_servers_agent_endpoint",
        ),
    )

    code: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(96), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ServerState.DISABLED.value,
        server_default=ServerState.DISABLED.value,
    )
    agent_host: Mapped[str] = mapped_column(String(253), nullable=False)
    agent_port: Mapped[int] = mapped_column(Integer, nullable=False, default=9443)
    public_host: Mapped[str] = mapped_column(String(253), nullable=False)
    wireguard_client_pool: Mapped[str | None] = mapped_column(CIDR)
    wireguard_gateway_address: Mapped[str | None] = mapped_column(INET)
    maximum_devices: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1000, server_default="1000"
    )

    def __repr__(self) -> str:
        return f"VPNServer(id={self.id!r}, code={self.code!r}, state={self.state!r})"


class ServerProtocolCapability(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Explicit enablement of one implemented profile on one VPN server.

    The referenced profile state is a cross-table service invariant. Callers must
    require ``IMPLEMENTABLE_PROFILE_STATE`` before enabling this capability.
    """

    IMPLEMENTABLE_PROFILE_STATE: ClassVar[str] = ProfileState.IMPLEMENTED.value

    __tablename__ = "server_protocol_capabilities"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(CapabilityState))})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            "capacity_limit IS NULL OR capacity_limit BETWEEN 1 AND 100000",
            name="capacity_limit_range",
        ),
        CheckConstraint(
            "validated_profile_version IS NULL OR "
            "length(validated_profile_version) BETWEEN 1 AND 32",
            name="validated_profile_version_length",
        ),
        UniqueConstraint(
            "vpn_server_id",
            "protocol_profile_id",
            name="uq_server_protocol_capabilities_server_profile",
        ),
    )

    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    protocol_profile_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("protocol_profiles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=CapabilityState.DISABLED.value,
        server_default=CapabilityState.DISABLED.value,
    )
    validated_profile_version: Mapped[str | None] = mapped_column(String(32))
    capacity_limit: Mapped[int | None] = mapped_column(Integer)

    def __repr__(self) -> str:
        return (
            "ServerProtocolCapability("
            f"id={self.id!r}, server_id={self.vpn_server_id!r}, "
            f"profile_id={self.protocol_profile_id!r}, state={self.state!r})"
        )


class UserServerAssignment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Temporal placement of a user on a VPN server."""

    __tablename__ = "user_server_assignments"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({_sql_vocabulary(values(LifecycleState))})",
            name="state_vocabulary",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > assigned_at",
            name="expiry_after_assignment",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= assigned_at",
            name="revocation_after_assignment",
        ),
        CheckConstraint(
            "(state = 'active' AND revoked_at IS NULL) OR "
            "(state = 'revoked' AND revoked_at IS NOT NULL)",
            name="state_revocation_pair",
        ),
        Index(
            "uq_user_server_assignments_active_user_server",
            "user_id",
            "vpn_server_id",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
        Index("ix_user_server_assignments_server_state", "vpn_server_id", "state"),
    )

    user_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    vpn_server_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("vpn_servers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assigned_by_admin_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="RESTRICT"),
    )
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=LifecycleState.ACTIVE.value,
        server_default=LifecycleState.ACTIVE.value,
    )
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return (
            "UserServerAssignment("
            f"id={self.id!r}, user_id={self.user_id!r}, "
            f"server_id={self.vpn_server_id!r}, state={self.state!r})"
        )
