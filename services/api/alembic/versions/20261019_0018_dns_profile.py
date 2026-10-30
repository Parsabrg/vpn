"""DNS profiles: which resolver an account's or a device's tunnel is given.

Revision ID: 20261019_0018
Revises: 20260917_0017
Create Date: 2026-10-19

Roadmap sections 13 and 108 (D27-D29). An account has a profile -- default
(the deployment's own resolver), ads, or family -- and a device may override
it. Plain strings with a check constraint, like the other short vocabularies
here, so a new profile is a constraint change rather than an enum migration.
"""

import sqlalchemy as sa

from alembic import op

revision = "20261019_0018"
down_revision = "20260917_0017"
branch_labels = None
depends_on = None

_PROFILES = "('default', 'ads', 'family')"


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("dns_profile", sa.String(length=16), nullable=False, server_default="default"),
    )
    op.create_check_constraint(
        op.f("ck_users_dns_profile_known"), "users", f"dns_profile IN {_PROFILES}"
    )
    op.add_column("devices", sa.Column("dns_profile", sa.String(length=16), nullable=True))
    op.create_check_constraint(
        op.f("ck_devices_dns_profile_known"),
        "devices",
        f"dns_profile IS NULL OR dns_profile IN {_PROFILES}",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_devices_dns_profile_known"), "devices", type_="check")
    op.drop_column("devices", "dns_profile")
    op.drop_constraint(op.f("ck_users_dns_profile_known"), "users", type_="check")
    op.drop_column("users", "dns_profile")
