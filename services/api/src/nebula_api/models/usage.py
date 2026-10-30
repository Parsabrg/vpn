"""Accumulated traffic per credential.

The agent reports what each serving process currently says, and every one of
those counters resets: Xray's and Hysteria's on restart, WireGuard's when a
peer is removed and re-added. So the durable total lives here, and each row
remembers the last raw reading it saw in order to turn a sequence of
resettable counters into something that only goes up.

Keyed by `(protocol, identity)` rather than by device, because that is what
the agent can actually observe. A WireGuard public key and an Xray client
UUID are the identifiers the serving process knows; mapping them to a device
is the control plane's job and is done at read time, so a credential the
control plane has forgotten still has its bytes recorded rather than dropped.
"""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class CredentialUsage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One credential's running totals, and the reading they were built from."""

    __tablename__ = "credential_usage"
    __table_args__ = (
        UniqueConstraint("protocol", "identity", name="one_row_per_credential"),
        CheckConstraint("rx_bytes >= 0 AND tx_bytes >= 0", name="totals_are_not_negative"),
        CheckConstraint(
            "last_rx_reading >= 0 AND last_tx_reading >= 0",
            name="readings_are_not_negative",
        ),
    )

    # "wireguard", "xray" or "hysteria2" -- the serving process, not the
    # protocol profile, since one profile can be served by either engine.
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)

    # The WireGuard public key, or the client UUID. Wide enough for a base64
    # key, which is the longest of the three.
    identity: Mapped[str] = mapped_column(String(64), nullable=False)

    # Monotonic totals. BigInteger because a busy credential passes 2 GB in an
    # afternoon and an int4 column would wrap silently.
    rx_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    tx_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")

    # The last raw counter seen. A new reading below this one means the
    # serving process restarted, and the whole new reading is the delta.
    last_rx_reading: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    last_tx_reading: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )

    # When the control plane asked for the reading the last figures came from.
    # A reading asked for earlier is older than what this row holds and is
    # ignored, so two overlapping reads cannot undo each other.
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # When the counters were last observed to move, which is not the same as
    # when this row was last written: a poll that finds no change still
    # updates updated_at.
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
