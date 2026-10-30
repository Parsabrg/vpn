"""Live credentials are unique per server, not per device.

Revision ID: 20261030_0019
Revises: 20261019_0018
Create Date: 2026-10-30

With a second server a device holds a credential on each. The live-uniqueness
rules named the device and profile but not the server, so a request to the
second server reused the first server's client.
"""

from alembic import op

revision = "20261030_0019"
down_revision = "20261019_0018"
branch_labels = None
depends_on = None

_LIVE = "state IN ('requested', 'applying', 'active', 'revoking')"

# name, table, old columns, new columns
_INDEXES = (
    (
        "uq_device_protocol_credentials_live_device_profile",
        "device_protocol_credentials",
        ["device_id", "protocol_profile_id"],
        ["device_id", "protocol_profile_id", "vpn_server_id"],
    ),
    (
        "uq_xray_clients_live_device_profile",
        "xray_clients",
        ["device_id", "protocol_profile_id"],
        ["device_id", "protocol_profile_id", "vpn_server_id"],
    ),
    (
        "uq_wireguard_peers_public_key_live",
        "wireguard_peers",
        ["public_key"],
        ["vpn_server_id", "public_key"],
    ),
    (
        "uq_wireguard_peers_live_device",
        "wireguard_peers",
        ["device_id"],
        ["device_id", "vpn_server_id"],
    ),
)


def _swap(use_new: bool) -> None:
    for name, table, old, new in _INDEXES:
        op.drop_index(name, table_name=table)
        op.create_index(
            name,
            table,
            new if use_new else old,
            unique=True,
            postgresql_where=_LIVE,
        )


def upgrade() -> None:
    _swap(use_new=True)


def downgrade() -> None:
    _swap(use_new=False)
