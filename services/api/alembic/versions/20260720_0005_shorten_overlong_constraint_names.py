"""Shorten two check constraint names that exceed Postgres's 63-char limit.

The logical names `ck_device_protocol_credentials_wireguard_has_no_encrypted_secret`
and `ck_server_protocol_capabilities_validated_profile_version_length` are 64
characters -- one over Postgres's NAMEDATALEN-1 identifier limit. sqlalchemy's
naming-convention compiler doesn't just truncate an over-length generated name;
it truncates *and appends an 8-character deterministic hash* (confirmed by
compiling `CreateTable` under `sqlalchemy.dialects.postgresql.dialect()`
directly), so the names actually stored in the catalog are
`ck_device_protocol_credentials_wireguard_has_no_encrypt_feb7` and
`ck_server_protocol_capabilities_validated_profile_versi_c3ef` -- not a plain
63-character left-truncation of the logical name (an earlier version of this
migration assumed that and failed in CI with "constraint ... does not
exist"). sqlalchemy 2.0.51's `alembic check` compared against this same
hash-truncated form, so it agreed with the catalog; sqlalchemy 2.0.52 changed
that comparison to use the full, untruncated logical name, so `alembic check`
now reports a permanent, unresolvable diff -- blocking the sqlalchemy/alembic
dependency bump. This renames the *actual*, hash-truncated names (`RENAME
CONSTRAINT` requires the name exactly as currently stored) to new, shorter
names that fit under the limit outright, with no truncation or hashing
involved on either side going forward. Pure identifier rename -- same table,
same check expression, no data or structural change -- so it's a fast,
catalog-only `RENAME CONSTRAINT`.

Revision ID: 20260720_0005
Revises: 20260720_0004
"""

from alembic import op

revision = "20260720_0005"
down_revision = "20260720_0004"
branch_labels = None
depends_on = None

_RENAMES = (
    (
        "device_protocol_credentials",
        # Actual, hash-truncated name stored in the catalog -- the
        # untruncated logical name is
        # ck_device_protocol_credentials_wireguard_has_no_encrypted_secret
        "ck_device_protocol_credentials_wireguard_has_no_encrypt_feb7",
        "ck_device_protocol_credentials_wireguard_no_encrypted_secret",
    ),
    (
        "server_protocol_capabilities",
        # Actual, hash-truncated name stored in the catalog -- the
        # untruncated logical name is
        # ck_server_protocol_capabilities_validated_profile_version_length
        "ck_server_protocol_capabilities_validated_profile_versi_c3ef",
        "ck_server_protocol_capabilities_validated_version_length",
    ),
)


def upgrade() -> None:
    for table, old_name, new_name in _RENAMES:
        op.execute(f'ALTER TABLE {table} RENAME CONSTRAINT "{old_name}" TO "{new_name}"')


def downgrade() -> None:
    for table, old_name, new_name in reversed(_RENAMES):
        op.execute(f'ALTER TABLE {table} RENAME CONSTRAINT "{new_name}" TO "{old_name}"')
