"""Who this installation is.

Every install of this project is its own control plane with its own database,
so isolation between installations is physical: Alice's rows are in Alice's
Postgres and cannot appear in yours whatever any query does. That is a
stronger guarantee than filtering by a tenant column, and it is the reason
there is no `deployment_id` on every table.

What a deployment identity is for, then, is not isolation but *recognition*:

  - a client can ask which deployment a URL belongs to, and notice when the
    answer changes -- pointing an app at a different control plane should be a
    deliberate act, not something that happens silently because a DNS record
    moved;
  - a VPN node can be enrolled into this deployment and no other;
  - a backup or a log can be attributed to the install it came from.

The identity is public. The deployment's *secret* is not, lives in the secrets
directory with the other key material, and never reaches the database or any
client.
"""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Deployment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """This installation's identity. Exactly one row, forever.

    The single-row rule is enforced by the database rather than by the code
    that writes it, because "do not regenerate the identity" is the whole
    requirement. Initialization is meant to be safe to run repeatedly -- on
    every container start, by an operator who is not sure whether it already
    ran, by a restart loop -- and a second identity would silently orphan
    every node enrolled against the first.
    """

    __tablename__ = "deployments"
    __table_args__ = (
        CheckConstraint("length(name) BETWEEN 1 AND 96", name="name_length"),
        # One row, enforced on a constant: any second insert collides whatever
        # its values are. A unique constraint on a column could not express
        # this, because there is no column whose value is the same in every
        # row by definition.
        Index("uq_deployments_singleton", text("(true)"), unique=True),
    )

    # What an operator calls this install. Shown to a client deciding whether
    # the URL it was given is the deployment it expects; never used as the
    # identity, because two people may well both call theirs "Home".
    name: Mapped[str] = mapped_column(String(96), nullable=False)

    # Who administers this install, recorded as deployment configuration
    # rather than as an account. Configuration, not a credential: it is shown
    # in the panel and used to address the operator, and it is deliberately
    # separate from whether an administrator account actually exists -- the
    # email can be set by an environment variable at first start, while
    # creating the account needs a password nothing here should invent.
    admin_email: Mapped[str | None] = mapped_column(String(320))

    # When initialization first completed. Distinct from `created_at`: a row
    # exists from the moment the identity is generated, and this records that
    # the rest of the bootstrap -- admin, keys, node -- also finished.
    initialized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
