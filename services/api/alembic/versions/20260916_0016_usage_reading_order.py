"""Remember when each credential's last counter reading was taken.

Counters are now read at more than one moment: by the periodic poll, and
immediately before and after every change that can restart the process
serving them. Two of those reads can overlap, and whichever is recorded last
used to win -- so a poll that read a process just before it restarted, and
was recorded just after, would put the old process's figure back as the last
reading and count it a second time.

`last_collected_at` is when the control plane asked for the reading that
row's last figures came from. A reading asked for earlier than that is older
than what the row already holds and is ignored. It is the control plane's
clock, not the agent's: every reading of one row is compared against another
taken by the same deployment, so there is no skew between machines to allow
for.

Nullable, and null for every existing row: a row nobody has read since this
revision has nothing to be newer than.

Revision ID: 20260916_0016
Revises: 20260912_0015
"""

import sqlalchemy as sa

from alembic import op

revision = "20260916_0016"
down_revision = "20260912_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "credential_usage",
        sa.Column("last_collected_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("credential_usage", "last_collected_at")
