"""Scope wireguard_peers' address uniqueness to live peers only.

The prior unconditional UniqueConstraint on (vpn_server_id,
assigned_address) meant a revoked or failed peer's address could never be
reused -- every address ever allocated for a server was permanently burned,
regardless of whether the peer holding it was still live. Replaces it with
a partial unique index scoped to the same live-state set already used by
the sibling `uq_wireguard_peers_live_device` index on this table, so an
address becomes reusable once its peer is confirmed revoked or failed.
Pure constraint-shape change -- no data migration, no existing row is
touched.

Revision ID: 20260720_0006
Revises: 20260720_0005
"""

import sqlalchemy as sa

from alembic import op

revision = "20260720_0006"
down_revision = "20260720_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("uq_wireguard_peers_server_address", "wireguard_peers", type_="unique")
    op.create_index(
        "uq_wireguard_peers_server_address_live",
        "wireguard_peers",
        ["vpn_server_id", "assigned_address"],
        unique=True,
        postgresql_where=sa.text("state IN ('requested', 'applying', 'active', 'revoking')"),
    )


def downgrade() -> None:
    op.drop_index("uq_wireguard_peers_server_address_live", table_name="wireguard_peers")
    op.create_unique_constraint(
        "uq_wireguard_peers_server_address",
        "wireguard_peers",
        ["vpn_server_id", "assigned_address"],
    )
