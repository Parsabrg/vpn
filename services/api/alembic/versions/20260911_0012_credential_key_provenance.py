"""Record which key encrypted a credential, and when a key is known lost.

`key_version` was never enough to identify the key that wrote a ciphertext. A
key can be replaced while its version stays the same, and nothing in the
envelope records which one was used -- so a regenerated key silently orphans
every credential written before it, and the only symptom is decryption
failing much later for reasons nobody can trace.

That is exactly what happened on this deployment: the Xray encryption key was
created seventeen minutes after the first credentials were written, reusing
version 1, with no previous-keys directory configured. Fourteen credentials
became permanently undecryptable and it took a byte-level audit and a file
birth timestamp to establish why.

`key_fingerprint` makes the key identifiable -- a non-secret digest, safe to
store and to print, so a swap can be stated rather than deduced.

`key_material_lost_at` records a conclusion rather than a symptom. A
credential whose key is gone will fail to decrypt on every read forever;
marking it says so once, which keeps a permanent, understood condition from
drowning out a new and genuine one.

Both nullable: existing rows have neither, and that absence is meaningful --
it means "written before anything recorded this".

Revision ID: 20260911_0012
Revises: 20260907_0011
"""

import sqlalchemy as sa

from alembic import op

revision = "20260911_0012"
down_revision = "20260907_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "device_protocol_credentials",
        sa.Column("key_fingerprint", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "device_protocol_credentials",
        sa.Column("key_material_lost_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("device_protocol_credentials", "key_material_lost_at")
    op.drop_column("device_protocol_credentials", "key_fingerprint")
