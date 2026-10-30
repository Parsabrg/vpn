"""Give Hysteria2 its own protocol engine.

Every non-WireGuard protocol was pinned to engine='xray' by the
code_engine_pair CHECK constraint, which was true when it was written and is
not any more. Xray-core accepts Hysteria2's Salamander obfuscation setting and
silently discards it -- a client offering a deliberately wrong password
authenticates successfully -- so an inbound configured for obfuscation has
none, and a client applying real Salamander cannot reach it at all. Hysteria2
is served by the reference binary in its own unit instead; see docs/adr/0003.

The row said 'xray' and nothing behaved differently for it, because dispatch
keys off the profile code rather than the engine. That is exactly what makes
it worth correcting: a column that is read by humans and not by code will be
believed.

Revision ID: 20260903_0008
Revises: 20260831_0007
"""

from alembic import op

revision = "20260903_0008"
down_revision = "20260831_0007"
branch_labels = None
depends_on = None

_OLD_PAIR = (
    "(code = 'wireguard' AND engine = 'native_wireguard') OR "
    "(code <> 'wireguard' AND engine = 'xray')"
)
_NEW_PAIR = (
    "(code = 'wireguard' AND engine = 'native_wireguard') OR "
    "(code = 'hysteria2' AND engine = 'hysteria') OR "
    "(code NOT IN ('wireguard', 'hysteria2') AND engine = 'xray')"
)

_OLD_VOCABULARY = "engine IN ('native_wireguard', 'xray')"
_NEW_VOCABULARY = "engine IN ('native_wireguard', 'xray', 'hysteria')"


def upgrade() -> None:
    # Names here are the bare ones: the metadata naming convention adds the
    # `ck_<table>_` prefix on both create and drop, so passing the full stored
    # name asks for `ck_protocols_ck_protocols_...` and fails.

    # Widen the vocabulary first, or the new value is not admissible at all.
    op.drop_constraint("engine_vocabulary", "protocols", type_="check")
    op.create_check_constraint("engine_vocabulary", "protocols", _NEW_VOCABULARY)

    # The row has to move while no pairing constraint is in force. Creating
    # the new pairing first fails, because the existing row still says 'xray'
    # and a CHECK is validated against the whole table when it is added.
    op.drop_constraint("code_engine_pair", "protocols", type_="check")
    op.execute("UPDATE protocols SET engine = 'hysteria' WHERE code = 'hysteria2'")
    op.create_check_constraint("code_engine_pair", "protocols", _NEW_PAIR)


def downgrade() -> None:
    op.drop_constraint("code_engine_pair", "protocols", type_="check")
    op.execute("UPDATE protocols SET engine = 'xray' WHERE code = 'hysteria2'")
    op.create_check_constraint("code_engine_pair", "protocols", _OLD_PAIR)

    # Narrow the vocabulary last, once nothing uses the value being removed.
    op.drop_constraint("engine_vocabulary", "protocols", type_="check")
    op.create_check_constraint("engine_vocabulary", "protocols", _OLD_VOCABULARY)
