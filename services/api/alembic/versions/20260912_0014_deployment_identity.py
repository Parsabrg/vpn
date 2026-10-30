"""Give the installation an identity of its own.

Until now nothing in the schema said which install it belonged to, because
there was only ever meant to be one. Self-hosting changes that: anyone can run
this, and a client pointed at a URL needs to be able to tell which deployment
answered -- so that moving an app between control planes is a deliberate act
rather than something a changed DNS record does quietly.

Isolation between installs is *physical*, not a column: each deployment owns
its own database. That is why this adds one row rather than a `deployment_id`
on every table. A tenant column would be a weaker guarantee (every query
becomes a place to forget it) for a separation the deployment model already
provides absolutely.

The single-row rule is enforced here rather than in the code that writes it.
Initialization is meant to be safe to run repeatedly, and a second identity
would silently orphan every node enrolled against the first -- so the database
refuses one, whatever the caller intended.

Revision ID: 20260912_0014
Revises: 20260911_0013
"""

import sqlalchemy as sa

from alembic import op

revision = "20260912_0014"
down_revision = "20260911_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "deployments",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=96), nullable=False),
        sa.Column("admin_email", sa.String(length=320), nullable=True),
        sa.Column("initialized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("length(name) BETWEEN 1 AND 96", name="name_length"),
    )
    # Unique on a constant: every row collides with every other, whatever
    # their values. No column could express this, because none has the same
    # value in every row by definition.
    op.create_index(
        "uq_deployments_singleton",
        "deployments",
        [sa.text("(true)")],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_deployments_singleton", table_name="deployments")
    op.drop_table("deployments")
