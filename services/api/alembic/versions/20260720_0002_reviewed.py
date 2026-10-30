"""Create reviewed protocol, topology, permission, and provisioning tables."""

# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260720_0002"
down_revision: str | None = "20260720_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "protocols",
        sa.Column("code", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=64), nullable=False),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("is_user_selectable", sa.Boolean(), server_default="true", nullable=False),
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
            "(code = 'wireguard' AND engine = 'native_wireguard') OR (code <> 'wireguard' AND engine = 'xray')",
            name=op.f("ck_protocols_code_engine_pair"),
        ),
        sa.CheckConstraint(
            "code IN ('wireguard', 'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2')",
            name=op.f("ck_protocols_code_vocabulary"),
        ),
        sa.CheckConstraint(
            "engine IN ('native_wireguard', 'xray')", name=op.f("ck_protocols_engine_vocabulary")
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 64", name=op.f("ck_protocols_display_name_length")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_protocols")),
        sa.UniqueConstraint("code", name="uq_protocols_code"),
    )

    op.create_table(
        "protocol_profiles",
        sa.Column("protocol_id", sa.UUID(), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("display_name", sa.String(length=96), nullable=False),
        sa.Column("state", sa.String(length=24), server_default="draft", nullable=False),
        sa.Column("transport", sa.String(length=24), nullable=True),
        sa.Column("transport_security", sa.String(length=16), nullable=True),
        sa.Column("flow", sa.String(length=24), nullable=True),
        sa.Column("template_key", sa.String(length=96), nullable=True),
        sa.Column("template_version", sa.String(length=32), nullable=True),
        sa.Column("required_port", sa.Integer(), nullable=True),
        sa.Column("requires_udp", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("is_full_tunnel", sa.Boolean(), server_default="true", nullable=False),
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
            "flow IS NULL OR flow IN ('xtls_vision')",
            name=op.f("ck_protocol_profiles_flow_vocabulary"),
        ),
        sa.CheckConstraint(
            "state IN ('draft', 'validated', 'implemented', 'deprecated')",
            name=op.f("ck_protocol_profiles_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "template_key IS NULL OR template_key ~ '^[a-z0-9][a-z0-9_.-]{0,95}$'",
            name=op.f("ck_protocol_profiles_template_key_format"),
        ),
        sa.CheckConstraint(
            "transport IS NULL OR transport IN ('raw', 'xhttp', 'mkcp', 'grpc', 'websocket', 'httpupgrade', 'hysteria')",
            name=op.f("ck_protocol_profiles_transport_vocabulary"),
        ),
        sa.CheckConstraint(
            "transport_security IS NULL OR transport_security IN ('tls', 'reality')",
            name=op.f("ck_protocol_profiles_transport_security_vocabulary"),
        ),
        sa.CheckConstraint(
            "length(code) BETWEEN 1 AND 64", name=op.f("ck_protocol_profiles_code_length")
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 96",
            name=op.f("ck_protocol_profiles_display_name_length"),
        ),
        sa.CheckConstraint(
            "required_port IS NULL OR required_port BETWEEN 1 AND 65535",
            name=op.f("ck_protocol_profiles_required_port_range"),
        ),
        sa.CheckConstraint(
            "template_version IS NULL OR length(template_version) BETWEEN 1 AND 32",
            name=op.f("ck_protocol_profiles_template_version_length"),
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_protocol_profiles_version_positive")),
        sa.ForeignKeyConstraint(
            ["protocol_id"],
            ["protocols.id"],
            name=op.f("fk_protocol_profiles_protocol_id_protocols"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_protocol_profiles")),
        sa.UniqueConstraint("code", "version", name="uq_protocol_profiles_code_version"),
        sa.UniqueConstraint(
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

    op.create_table(
        "protocol_profile_platforms",
        sa.Column("protocol_profile_id", sa.UUID(), nullable=False),
        sa.Column("platform", sa.String(length=16), nullable=False),
        sa.Column("minimum_client_version", sa.String(length=32), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), server_default="false", nullable=False),
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
            "platform IN ('android', 'windows')",
            name=op.f("ck_protocol_profile_platforms_platform_vocabulary"),
        ),
        sa.CheckConstraint(
            "minimum_client_version IS NULL OR length(minimum_client_version) BETWEEN 1 AND 32",
            name=op.f("ck_protocol_profile_platforms_minimum_client_version_length"),
        ),
        sa.ForeignKeyConstraint(
            ["protocol_profile_id"],
            ["protocol_profiles.id"],
            name=op.f("fk_protocol_profile_platforms_protocol_profile_id_protocol_profiles"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_protocol_profile_platforms")),
        sa.UniqueConstraint(
            "protocol_profile_id", "platform", name="uq_protocol_profile_platforms_profile_platform"
        ),
    )

    op.create_table(
        "user_protocol_permissions",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("protocol_profile_id", sa.UUID(), nullable=False),
        sa.Column("granted_by_admin_id", sa.UUID(), nullable=True),
        sa.Column("state", sa.String(length=16), server_default="disabled", nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
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
            "(state = 'enabled' AND revoked_at IS NULL) OR (state = 'disabled')",
            name=op.f("ck_user_protocol_permissions_enabled_not_revoked"),
        ),
        sa.CheckConstraint(
            "state IN ('enabled', 'disabled')",
            name=op.f("ck_user_protocol_permissions_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > granted_at",
            name=op.f("ck_user_protocol_permissions_expiry_after_grant"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= granted_at",
            name=op.f("ck_user_protocol_permissions_revocation_after_grant"),
        ),
        sa.ForeignKeyConstraint(
            ["granted_by_admin_id"],
            ["admin_users.id"],
            name=op.f("fk_user_protocol_permissions_granted_by_admin_id_admin_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["protocol_profile_id"],
            ["protocol_profiles.id"],
            name=op.f("fk_user_protocol_permissions_protocol_profile_id_protocol_profiles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_protocol_permissions_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_protocol_permissions")),
        sa.UniqueConstraint(
            "user_id", "protocol_profile_id", name="uq_user_protocol_permissions_user_profile"
        ),
    )

    op.create_table(
        "vpn_servers",
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=96), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="disabled", nullable=False),
        sa.Column("agent_host", sa.String(length=253), nullable=False),
        sa.Column("agent_port", sa.Integer(), nullable=False),
        sa.Column("public_host", sa.String(length=253), nullable=False),
        sa.Column("wireguard_client_pool", postgresql.CIDR(), nullable=True),
        sa.Column("wireguard_gateway_address", postgresql.INET(), nullable=True),
        sa.Column("maximum_devices", sa.Integer(), server_default="1000", nullable=False),
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
            "length(agent_host) BETWEEN 1 AND 253 AND agent_host !~ '[/:@[:space:]]'",
            name=op.f("ck_vpn_servers_agent_host_format"),
        ),
        sa.CheckConstraint(
            "length(public_host) BETWEEN 1 AND 253 AND public_host !~ '[/:@[:space:]]'",
            name=op.f("ck_vpn_servers_public_host_format"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'maintenance', 'disabled')",
            name=op.f("ck_vpn_servers_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "agent_port BETWEEN 1 AND 65535", name=op.f("ck_vpn_servers_agent_port_range")
        ),
        sa.CheckConstraint(
            "length(code) BETWEEN 1 AND 64", name=op.f("ck_vpn_servers_code_length")
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 96", name=op.f("ck_vpn_servers_display_name_length")
        ),
        sa.CheckConstraint(
            "maximum_devices BETWEEN 1 AND 100000",
            name=op.f("ck_vpn_servers_maximum_devices_range"),
        ),
        sa.CheckConstraint(
            "wireguard_gateway_address IS NULL OR (wireguard_client_pool IS NOT NULL AND wireguard_gateway_address <<= wireguard_client_pool AND masklen(wireguard_gateway_address) IN (32, 128))",
            name=op.f("ck_vpn_servers_gateway_in_pool"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vpn_servers")),
        sa.UniqueConstraint("agent_host", "agent_port", name="uq_vpn_servers_agent_endpoint"),
        sa.UniqueConstraint("code", name="uq_vpn_servers_code"),
    )

    op.create_table(
        "server_protocol_capabilities",
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("protocol_profile_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="disabled", nullable=False),
        sa.Column("validated_profile_version", sa.String(length=32), nullable=True),
        sa.Column("capacity_limit", sa.Integer(), nullable=True),
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
            "state IN ('enabled', 'disabled')",
            name=op.f("ck_server_protocol_capabilities_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "capacity_limit IS NULL OR capacity_limit BETWEEN 1 AND 100000",
            name=op.f("ck_server_protocol_capabilities_capacity_limit_range"),
        ),
        sa.CheckConstraint(
            "validated_profile_version IS NULL OR length(validated_profile_version) BETWEEN 1 AND 32",
            name=op.f("ck_server_protocol_capabilities_validated_profile_version_length"),
        ),
        sa.ForeignKeyConstraint(
            ["protocol_profile_id"],
            ["protocol_profiles.id"],
            name=op.f("fk_server_protocol_capabilities_protocol_profile_id_protocol_profiles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_server_protocol_capabilities_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_server_protocol_capabilities")),
        sa.UniqueConstraint(
            "vpn_server_id",
            "protocol_profile_id",
            name="uq_server_protocol_capabilities_server_profile",
        ),
    )

    op.create_table(
        "user_server_assignments",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("assigned_by_admin_id", sa.UUID(), nullable=True),
        sa.Column("state", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
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
            "(state = 'active' AND revoked_at IS NULL) OR (state = 'revoked' AND revoked_at IS NOT NULL)",
            name=op.f("ck_user_server_assignments_state_revocation_pair"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'revoked')",
            name=op.f("ck_user_server_assignments_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > assigned_at",
            name=op.f("ck_user_server_assignments_expiry_after_assignment"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= assigned_at",
            name=op.f("ck_user_server_assignments_revocation_after_assignment"),
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_admin_id"],
            ["admin_users.id"],
            name=op.f("fk_user_server_assignments_assigned_by_admin_id_admin_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_server_assignments_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_user_server_assignments_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_server_assignments")),
    )

    op.create_index(
        "ix_user_server_assignments_server_state",
        "user_server_assignments",
        ["vpn_server_id", "state"],
        unique=False,
    )

    op.create_index(
        "uq_user_server_assignments_active_user_server",
        "user_server_assignments",
        ["user_id", "vpn_server_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )

    op.create_table(
        "device_protocol_credentials",
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("protocol_profile_id", sa.UUID(), nullable=False),
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="requested", nullable=False),
        sa.Column("generation", sa.Integer(), server_default="1", nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("nonce", sa.LargeBinary(), nullable=True),
        sa.Column("key_version", sa.String(length=64), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
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
            "kind <> 'wireguard_public' OR (ciphertext IS NULL AND nonce IS NULL AND key_version IS NULL)",
            name=op.f("ck_device_protocol_credentials_wireguard_has_no_encrypted_secret"),
        ),
        sa.CheckConstraint(
            "kind <> 'xray_bearer' OR state NOT IN ('active', 'revoking') OR ciphertext IS NOT NULL",
            name=op.f("ck_device_protocol_credentials_active_xray_has_encrypted_secret"),
        ),
        sa.CheckConstraint(
            "kind IN ('wireguard_public', 'xray_bearer')",
            name=op.f("ck_device_protocol_credentials_kind_vocabulary"),
        ),
        sa.CheckConstraint(
            "state <> 'revoked' OR revoked_at IS NOT NULL",
            name=op.f("ck_device_protocol_credentials_revoked_state_timestamp"),
        ),
        sa.CheckConstraint(
            "state IN ('requested', 'applying', 'active', 'revoking', 'revoked', 'failed')",
            name=op.f("ck_device_protocol_credentials_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "(ciphertext IS NULL AND nonce IS NULL AND key_version IS NULL) OR (ciphertext IS NOT NULL AND nonce IS NOT NULL AND key_version IS NOT NULL)",
            name=op.f("ck_device_protocol_credentials_aead_tuple_complete"),
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > issued_at",
            name=op.f("ck_device_protocol_credentials_expiry_after_issue"),
        ),
        sa.CheckConstraint(
            "generation >= 1", name=op.f("ck_device_protocol_credentials_generation_positive")
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= issued_at",
            name=op.f("ck_device_protocol_credentials_revocation_after_issue"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_device_protocol_credentials_device_id_devices"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["protocol_profile_id"],
            ["protocol_profiles.id"],
            name=op.f("fk_device_protocol_credentials_protocol_profile_id_protocol_profiles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_device_protocol_credentials_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_device_protocol_credentials")),
        sa.UniqueConstraint(
            "id",
            "kind",
            "device_id",
            "protocol_profile_id",
            "vpn_server_id",
            name="uq_device_protocol_credentials_runtime_identity",
        ),
    )

    op.create_index(
        "ix_device_protocol_credentials_server_state",
        "device_protocol_credentials",
        ["vpn_server_id", "state"],
        unique=False,
    )

    op.create_index(
        "uq_device_protocol_credentials_live_device_profile",
        "device_protocol_credentials",
        ["device_id", "protocol_profile_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('requested', 'applying', 'active', 'revoking')"),
    )

    op.create_table(
        "wireguard_peers",
        sa.Column("credential_id", sa.UUID(), nullable=False),
        sa.Column(
            "credential_kind",
            sa.String(length=24),
            server_default="wireguard_public",
            nullable=False,
        ),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("protocol_profile_id", sa.UUID(), nullable=False),
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("public_key", sa.String(length=44), nullable=False),
        sa.Column("assigned_address", postgresql.INET(), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="requested", nullable=False),
        sa.Column("applied_generation", sa.Integer(), server_default="0", nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
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
            "credential_kind = 'wireguard_public'",
            name=op.f("ck_wireguard_peers_credential_kind_wireguard"),
        ),
        sa.CheckConstraint(
            "public_key ~ '^[A-Za-z0-9+/]{43}=$' AND public_key <> 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
            name=op.f("ck_wireguard_peers_public_key_canonical"),
        ),
        sa.CheckConstraint(
            "state IN ('requested', 'applying', 'active', 'revoking', 'revoked', 'failed')",
            name=op.f("ck_wireguard_peers_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "applied_generation >= 0",
            name=op.f("ck_wireguard_peers_applied_generation_nonnegative"),
        ),
        sa.CheckConstraint(
            "masklen(assigned_address) IN (32, 128)",
            name=op.f("ck_wireguard_peers_assigned_address_is_host"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR applied_at IS NULL OR revoked_at >= applied_at",
            name=op.f("ck_wireguard_peers_revocation_after_apply"),
        ),
        sa.ForeignKeyConstraint(
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
            name="fk_wireguard_peers_credential_identity",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_wireguard_peers_device_id_devices"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["protocol_profile_id"],
            ["protocol_profiles.id"],
            name=op.f("fk_wireguard_peers_protocol_profile_id_protocol_profiles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_wireguard_peers_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_wireguard_peers")),
        sa.UniqueConstraint("credential_id", name="uq_wireguard_peers_credential"),
        sa.UniqueConstraint("public_key", name="uq_wireguard_peers_public_key"),
        sa.UniqueConstraint(
            "vpn_server_id", "assigned_address", name="uq_wireguard_peers_server_address"
        ),
    )

    op.create_index(
        "ix_wireguard_peers_server_state",
        "wireguard_peers",
        ["vpn_server_id", "state"],
        unique=False,
    )

    op.create_index(
        "uq_wireguard_peers_live_device",
        "wireguard_peers",
        ["device_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('requested', 'applying', 'active', 'revoking')"),
    )

    op.create_table(
        "xray_clients",
        sa.Column("credential_id", sa.UUID(), nullable=False),
        sa.Column(
            "credential_kind", sa.String(length=24), server_default="xray_bearer", nullable=False
        ),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("protocol_profile_id", sa.UUID(), nullable=False),
        sa.Column("vpn_server_id", sa.UUID(), nullable=False),
        sa.Column("opaque_label", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="requested", nullable=False),
        sa.Column("applied_generation", sa.Integer(), server_default="0", nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
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
            "credential_kind = 'xray_bearer'", name=op.f("ck_xray_clients_credential_kind_xray")
        ),
        sa.CheckConstraint(
            "opaque_label ~ '^[A-Za-z0-9_-]{16,64}$'",
            name=op.f("ck_xray_clients_opaque_label_format"),
        ),
        sa.CheckConstraint(
            "state IN ('requested', 'applying', 'active', 'revoking', 'revoked', 'failed')",
            name=op.f("ck_xray_clients_state_vocabulary"),
        ),
        sa.CheckConstraint(
            "applied_generation >= 0", name=op.f("ck_xray_clients_applied_generation_nonnegative")
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR applied_at IS NULL OR revoked_at >= applied_at",
            name=op.f("ck_xray_clients_revocation_after_apply"),
        ),
        sa.ForeignKeyConstraint(
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
            name="fk_xray_clients_credential_identity",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_xray_clients_device_id_devices"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["protocol_profile_id"],
            ["protocol_profiles.id"],
            name=op.f("fk_xray_clients_protocol_profile_id_protocol_profiles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["vpn_server_id"],
            ["vpn_servers.id"],
            name=op.f("fk_xray_clients_vpn_server_id_vpn_servers"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_xray_clients")),
        sa.UniqueConstraint("credential_id", name="uq_xray_clients_credential"),
        sa.UniqueConstraint("opaque_label", name="uq_xray_clients_opaque_label"),
    )

    op.create_index(
        "ix_xray_clients_server_state", "xray_clients", ["vpn_server_id", "state"], unique=False
    )

    op.create_index(
        "uq_xray_clients_live_device_profile",
        "xray_clients",
        ["device_id", "protocol_profile_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('requested', 'applying', 'active', 'revoking')"),
    )


def downgrade() -> None:
    op.drop_table("xray_clients")
    op.drop_table("wireguard_peers")
    op.drop_table("device_protocol_credentials")
    op.drop_table("user_server_assignments")
    op.drop_table("server_protocol_capabilities")
    op.drop_table("vpn_servers")
    op.drop_table("user_protocol_permissions")
    op.drop_table("protocol_profile_platforms")
    op.drop_table("protocol_profiles")
    op.drop_table("protocols")
