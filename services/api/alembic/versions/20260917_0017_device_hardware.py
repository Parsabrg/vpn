"""Recognise a device across reinstall: a hashed hardware id on devices.

Revision ID: 20260917_0017
Revises: 20260916_0016
Create Date: 2026-10-08

A device's server id lives in app storage, which uninstalling wipes, so a
reinstall registered a second row for one phone and the account's device
count never came back down. The app now sends the platform's own install id;
the server keeps an HMAC of it (never the id itself) and reuses the device it
names. The partial-unique index keeps one active row per (account, hardware).
"""

import sqlalchemy as sa

from alembic import op

revision = "20260917_0017"
down_revision = "20260916_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("hardware_hash", sa.LargeBinary(length=32), nullable=True))
    op.add_column("devices", sa.Column("hardware_key_version", sa.Integer(), nullable=True))
    op.create_index(
        "uq_devices_user_hardware_active",
        "devices",
        ["user_id", "hardware_hash"],
        unique=True,
        postgresql_where=sa.text("state = 'active' AND hardware_hash IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_devices_user_hardware_active", table_name="devices")
    op.drop_column("devices", "hardware_key_version")
    op.drop_column("devices", "hardware_hash")
