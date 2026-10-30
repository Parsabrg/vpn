"""Record traffic per credential, and give an account an allowance.

Two things the system could not previously express: how much a credential has
transferred, and how much a user is allowed. The app's account screen wants
both -- "used" needs the first, "left" needs the second -- and neither had
anywhere to live.

`credential_usage` is keyed by `(protocol, identity)` rather than by device
because that is what the agent can observe: a WireGuard public key, or an Xray
or Hysteria client UUID. Mapping those to a device happens at read time, so a
credential the control plane has since forgotten still has its bytes recorded
rather than silently dropped.

Each row carries both a running total and the last raw counter it was built
from. Every source resets -- Xray and Hysteria on restart, WireGuard when a
peer is re-added -- so a reading lower than the last one means a restart, and
the whole new reading is the delta. Without the remembered reading there is no
way to tell a restart from a quiet period.

`users.traffic_quota_bytes` is nullable, and NULL means unmetered. A sentinel
"very large" number would make "no limit" indistinguishable from "a limit that
happens to be huge", and the difference is visible: one renders as no figure
at all, the other as a number somebody would eventually be shown.

Revision ID: 20260907_0011
Revises: 20260906_0010
"""

import sqlalchemy as sa

from alembic import op

revision = "20260907_0011"
down_revision = "20260906_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("traffic_quota_bytes", sa.BigInteger(), nullable=True))

    op.create_table(
        "credential_usage",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("identity", sa.String(length=64), nullable=False),
        # BigInteger throughout: a busy credential passes 2 GB in an
        # afternoon, and an int4 column would wrap without saying so.
        sa.Column("rx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_rx_reading", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_tx_reading", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "rx_bytes >= 0 AND tx_bytes >= 0",
            name="totals_are_not_negative",
        ),
        sa.CheckConstraint(
            "last_rx_reading >= 0 AND last_tx_reading >= 0",
            name="readings_are_not_negative",
        ),
        # The upsert the collector performs depends on this: one row per
        # credential, so a concurrent poll cannot create a second and split
        # the total between them.
        sa.UniqueConstraint("protocol", "identity", name="one_row_per_credential"),
    )


def downgrade() -> None:
    op.drop_table("credential_usage")
    op.drop_column("users", "traffic_quota_bytes")
