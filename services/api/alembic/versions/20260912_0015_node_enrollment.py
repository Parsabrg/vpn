"""Let a new VPN node join without an operator generating certificates.

Adding a second VPS used to mean making a certificate by hand, copying it to
the machine, and inserting a row -- a procedure that works when one person set
up one server and does not survive the project being self-hosted by anyone
else.

An enrollment token is the way out of the circularity: a node cannot
authenticate before it has an identity, and cannot have an identity before it
authenticates. An administrator mints a token, it travels to the new VPS by
whatever means the operator already trusts, and the node exchanges it for a
certificate signed by the deployment's own CA.

The token is stored as a keyed digest rather than as itself, single-use, and
short-lived, because in transit it is a bearer credential: anyone holding it
can enrol a node into this deployment until it is redeemed or expires. The row
survives redemption rather than being deleted -- "was that token ever used,
and when" is a security question, and a missing row answers it ambiguously.

Revision ID: 20260912_0015
Revises: 20260912_0014
"""

import sqlalchemy as sa

from alembic import op

revision = "20260912_0015"
down_revision = "20260912_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node_enrollment_tokens",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "vpn_server_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("vpn_servers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_by_admin_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("admin_users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("length(label) BETWEEN 1 AND 64", name="label_length"),
        sa.CheckConstraint("expires_at > created_at", name="expiry_after_issue"),
        sa.CheckConstraint("used_at IS NULL OR used_at >= created_at", name="use_after_issue"),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at", name="revocation_after_issue"
        ),
        sa.CheckConstraint(
            "used_at IS NULL OR revoked_at IS NULL", name="used_or_revoked_not_both"
        ),
    )
    op.create_index("ix_node_enrollment_tokens_digest", "node_enrollment_tokens", ["token_digest"])


def downgrade() -> None:
    op.drop_index("ix_node_enrollment_tokens_digest", table_name="node_enrollment_tokens")
    op.drop_table("node_enrollment_tokens")
