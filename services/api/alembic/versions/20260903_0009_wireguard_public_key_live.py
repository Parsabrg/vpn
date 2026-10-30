"""Scope WireGuard public-key uniqueness to live peers.

A client keeps its WireGuard keypair -- the private half never leaves the
device -- so reconnecting after a revoke legitimately presents the same public
key. `uq_wireguard_peers_public_key` spanned every row including revoked ones,
so a device could connect exactly once: every reconnect afterwards failed the
insert on a constraint the client had no way to satisfy short of discarding its
identity and becoming a different device.

It surfaced as a 500 from `POST /wireguard-peer` and "Request was not accepted"
in the app, with the real cause only in the API's traceback.

Every other uniqueness rule on this table is already scoped to live states
(`uq_wireguard_peers_server_address_live`, `uq_wireguard_peers_live_device`),
as is the equivalent on `xray_clients`. This one was the exception, which is
why only WireGuard had the problem.

Revision ID: 20260903_0009
Revises: 20260903_0008
"""

from alembic import op

revision = "20260903_0009"
down_revision = "20260903_0008"
branch_labels = None
depends_on = None

_LIVE = "state IN ('requested', 'applying', 'active', 'revoking')"


def upgrade() -> None:
    op.drop_constraint("uq_wireguard_peers_public_key", "wireguard_peers", type_="unique")
    op.create_index(
        "uq_wireguard_peers_public_key_live",
        "wireguard_peers",
        ["public_key"],
        unique=True,
        postgresql_where=_LIVE,
    )


def downgrade() -> None:
    # Reinstating the table-wide constraint requires that no key is repeated
    # across revoked rows. Peers that reconnected after this migration will
    # have produced exactly that, so drop the revoked duplicates -- they are
    # historical rows for a peer that has since been reissued, and the live one
    # is kept.
    op.execute(
        """
        DELETE FROM wireguard_peers wp
        WHERE wp.state NOT IN ('requested', 'applying', 'active', 'revoking')
          AND EXISTS (
              SELECT 1 FROM wireguard_peers other
              WHERE other.public_key = wp.public_key
                AND other.id <> wp.id
                AND (other.state IN ('requested', 'applying', 'active', 'revoking')
                     OR other.created_at > wp.created_at)
          )
        """
    )
    op.drop_index("uq_wireguard_peers_public_key_live", table_name="wireguard_peers")
    op.create_unique_constraint("uq_wireguard_peers_public_key", "wireguard_peers", ["public_key"])
