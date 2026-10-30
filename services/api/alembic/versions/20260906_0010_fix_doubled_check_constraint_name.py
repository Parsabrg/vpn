"""Fix a check constraint name that carries its table prefix twice.

Migration 0007 created the constraint with

    op.create_check_constraint("ck_protocol_profiles_agent_profile_code_format", ...)

but that first argument is the *bare* constraint name, which the metadata's
`ck_%(table_name)s_%(constraint_name)s` convention then prefixes again. The
logical name became
`ck_protocol_profiles_ck_protocol_profiles_agent_profile_code_format` -- 67
characters, over Postgres's 63-character identifier limit -- so SQLAlchemy
truncated it and appended its deterministic 8-character hash, exactly as
migration 0005 documents. The catalog therefore holds
`ck_protocol_profiles_ck_protocol_profiles_agent_profile_cbbb`, while
`ProtocolProfile.__table_args__` declares `name="agent_profile_code_format"`,
which renders as the 46-character `ck_protocol_profiles_agent_profile_code_format`.

The two have disagreed since 0007 landed. Nothing caught it because Alembic
did not compare check constraints at all before 1.19; the version bump made
this visible rather than causing it.

The old name is not read off a log line -- log output truncates, and 0005
failed in CI once for assuming a plain left-truncation. It was computed by
compiling `AddConstraint` under `sqlalchemy.dialects.postgresql.dialect()`,
which reproduces the catalog name including the hash suffix.

Pure identifier rename: same table, same predicate, no data or structural
change, so this is a catalog-only `RENAME CONSTRAINT`.

Revision ID: 20260906_0010
Revises: 20260903_0009
"""

from alembic import op

revision = "20260906_0010"
down_revision = "20260903_0009"
branch_labels = None
depends_on = None

_TABLE = "protocol_profiles"
# Actual, hash-truncated name in the catalog. The untruncated logical name is
# ck_protocol_profiles_ck_protocol_profiles_agent_profile_code_format
_OLD_NAME = "ck_protocol_profiles_ck_protocol_profiles_agent_profile_cbbb"
_NEW_NAME = "ck_protocol_profiles_agent_profile_code_format"


def upgrade() -> None:
    op.execute(f'ALTER TABLE {_TABLE} RENAME CONSTRAINT "{_OLD_NAME}" TO "{_NEW_NAME}"')


def downgrade() -> None:
    op.execute(f'ALTER TABLE {_TABLE} RENAME CONSTRAINT "{_NEW_NAME}" TO "{_OLD_NAME}"')
