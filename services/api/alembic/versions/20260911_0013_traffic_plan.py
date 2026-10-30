"""Make an allowance something that can be granted again.

`traffic_quota_bytes` alone could only express a lifetime cap. Topping an
account up meant raising that number forever, so the figure an operator typed
was never the size of the plan they were selling -- it was the sum of every
plan the account had ever had, which nobody can compute from a support
message.

`traffic_baseline_bytes` is the lifetime total at the moment the current
allowance was granted. What the account has used is everything since. Granting
a new allowance moves the mark to today's total, so the new plan starts at
zero while every per-credential total goes on accumulating and stays
auditable.

This is the same shape as the rest of the system's accounting: a counter that
only goes up, read against a remembered mark. Nothing is ever reset in place,
because a figure that can go down cannot be reconciled afterwards.

`quota_exhausted_at` records when an allowance was found spent and the
credentials taken away -- so the app can say why, and so a sweep that finds an
account already cut off does not revoke it again on every pass.

Revision ID: 20260911_0013
Revises: 20260911_0012
"""

import sqlalchemy as sa

from alembic import op

revision = "20260911_0013"
down_revision = "20260911_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "traffic_baseline_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "users",
        sa.Column("quota_exhausted_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "quota_exhausted_at")
    op.drop_column("users", "traffic_baseline_bytes")
