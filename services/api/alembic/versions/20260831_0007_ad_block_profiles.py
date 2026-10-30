"""Add ad_block and agent_profile_code to protocol_profiles.

Ad-blocking is a manually-selected sibling profile (e.g.
"vless-xhttp-tls-adblock"), not a per-device toggle -- it shows up in the
same picker as every other profile. `ad_block` marks such a sibling;
`agent_profile_code`, set only on a sibling, carries the REAL profile code
the agent's inbound is actually configured under (the sibling's own `code`
exists purely for user-facing selection/bookkeeping -- the agent has no
concept of ad-block variants at all).

Revision ID: 20260831_0007
Revises: 20260720_0006
"""

import sqlalchemy as sa

from alembic import op

revision = "20260831_0007"
down_revision = "20260720_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "protocol_profiles",
        sa.Column("ad_block", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "protocol_profiles",
        sa.Column("agent_profile_code", sa.String(length=64), nullable=True),
    )
    op.create_check_constraint(
        "ck_protocol_profiles_agent_profile_code_format",
        "protocol_profiles",
        "agent_profile_code IS NULL OR agent_profile_code ~ '^[a-z0-9][a-z0-9-]{0,63}$'",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_protocol_profiles_agent_profile_code_format",
        "protocol_profiles",
        type_="check",
    )
    op.drop_column("protocol_profiles", "agent_profile_code")
    op.drop_column("protocol_profiles", "ad_block")
