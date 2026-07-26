import asyncio
import os
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_api.db.engine import create_database_engine
from nebula_api.db.schema import SCHEMA_HEAD, schema_is_current


def fake_engine_for_revisions(revisions: list[str]) -> AsyncEngine:
    result = MagicMock()
    result.scalars.return_value = revisions
    connection = AsyncMock()
    connection.execute = AsyncMock(side_effect=[MagicMock(), result])
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=connection)
    context.__aexit__ = AsyncMock(return_value=False)
    engine = MagicMock()
    engine.connect.return_value = context
    return cast(AsyncEngine, engine)


def test_schema_is_current_requires_exactly_one_expected_head() -> None:
    assert asyncio.run(schema_is_current(fake_engine_for_revisions([SCHEMA_HEAD])))
    assert not asyncio.run(schema_is_current(fake_engine_for_revisions([])))
    assert not asyncio.run(
        schema_is_current(fake_engine_for_revisions([SCHEMA_HEAD, "unexpected"]))
    )


def test_schema_is_current_hides_database_failures() -> None:
    connection = AsyncMock()
    connection.execute = AsyncMock(side_effect=SQLAlchemyError("unavailable"))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=connection)
    context.__aexit__ = AsyncMock(return_value=False)
    engine = MagicMock()
    engine.connect.return_value = context

    assert not asyncio.run(schema_is_current(cast(AsyncEngine, engine)))


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_database_app_role_reads_schema_but_cannot_create_tables() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)

    async def assert_permissions() -> None:
        assert await schema_is_current(engine)
        with pytest.raises(ProgrammingError):
            async with engine.begin() as connection:
                await connection.execute(text("CREATE TABLE forbidden_app_ddl (id integer)"))

        audit_id = uuid4()
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO audit_logs "
                    "(id, actor_kind, target_kind, target_id, event_code, outcome) "
                    "VALUES (:id, 'bootstrap', 'admin', :target_id, "
                    "'admin_seeded', 'succeeded')"
                ),
                {"id": audit_id, "target_id": uuid4()},
            )
            count = await connection.scalar(
                text("SELECT count(*) FROM audit_logs WHERE id = :id"), {"id": audit_id}
            )
            assert count == 1

        for forbidden_statement in (
            "UPDATE audit_logs SET outcome = 'failed' WHERE id = :id",
            "DELETE FROM audit_logs WHERE id = :id",
            "UPDATE alembic_version SET version_num = version_num",
        ):
            with pytest.raises(ProgrammingError):
                async with engine.begin() as connection:
                    await connection.execute(text(forbidden_statement), {"id": audit_id})

    try:
        asyncio.run(assert_permissions())
    finally:
        asyncio.run(engine.dispose())


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_postgres_enforces_refresh_rotation_and_active_session_invariants() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)

    async def assert_constraints() -> None:
        user_id = uuid4()
        first_device_id = uuid4()
        second_device_id = uuid4()
        first_session_id = uuid4()
        second_session_id = uuid4()
        initial_token_id = uuid4()
        successor_token_id = uuid4()

        async with engine.connect() as connection:
            transaction = await connection.begin()
            try:
                await connection.execute(
                    text(
                        "INSERT INTO users "
                        "(id, email, email_normalized, password_hash, state, device_limit, "
                        "activated_at) VALUES "
                        "(:id, :email, :email, :password_hash, 'active', 3, now())"
                    ),
                    {
                        "id": user_id,
                        "email": f"{user_id}@example.test",
                        "password_hash": "integration-test-hash",
                    },
                )
                for device_id in (first_device_id, second_device_id):
                    await connection.execute(
                        text(
                            "INSERT INTO devices "
                            "(id, user_id, name, platform, client_version, state) VALUES "
                            "(:id, :user_id, 'Integration device', 'windows', '1.0', 'active')"
                        ),
                        {"id": device_id, "user_id": user_id},
                    )
                for session_id, device_id in (
                    (first_session_id, first_device_id),
                    (second_session_id, second_device_id),
                ):
                    await connection.execute(
                        text(
                            "INSERT INTO user_sessions "
                            "(id, user_id, device_id, family_id, state, expires_at) VALUES "
                            "(:id, :user_id, :device_id, :family_id, 'active', "
                            "now() + interval '1 day')"
                        ),
                        {
                            "id": session_id,
                            "user_id": user_id,
                            "device_id": device_id,
                            "family_id": uuid4(),
                        },
                    )
                await connection.execute(
                    text(
                        "INSERT INTO refresh_tokens "
                        "(id, session_id, token_digest, key_version, state, expires_at) VALUES "
                        "(:id, :session_id, :digest, 1, 'active', now() + interval '1 day')"
                    ),
                    {
                        "id": initial_token_id,
                        "session_id": first_session_id,
                        "digest": b"a" * 32,
                    },
                )

                await connection.execute(
                    text(
                        "SET CONSTRAINTS "
                        "fk_refresh_tokens_replacement_same_session_refresh_tokens DEFERRED"
                    )
                )
                await connection.execute(
                    text(
                        "UPDATE refresh_tokens SET state = 'consumed', consumed_at = now(), "
                        "replaced_by_id = :successor_id WHERE id = :initial_id"
                    ),
                    {"successor_id": successor_token_id, "initial_id": initial_token_id},
                )
                await connection.execute(
                    text(
                        "INSERT INTO refresh_tokens "
                        "(id, session_id, token_digest, key_version, state, expires_at) VALUES "
                        "(:id, :session_id, :digest, 1, 'active', now() + interval '1 day')"
                    ),
                    {
                        "id": successor_token_id,
                        "session_id": first_session_id,
                        "digest": b"b" * 32,
                    },
                )
                await connection.execute(
                    text(
                        "SET CONSTRAINTS "
                        "fk_refresh_tokens_replacement_same_session_refresh_tokens IMMEDIATE"
                    )
                )

                duplicate_session = await connection.begin_nested()
                try:
                    with pytest.raises(IntegrityError):
                        await connection.execute(
                            text(
                                "INSERT INTO user_sessions "
                                "(id, user_id, device_id, family_id, state, expires_at) VALUES "
                                "(:id, :user_id, :device_id, :family_id, 'active', "
                                "now() + interval '1 day')"
                            ),
                            {
                                "id": uuid4(),
                                "user_id": user_id,
                                "device_id": first_device_id,
                                "family_id": uuid4(),
                            },
                        )
                finally:
                    await duplicate_session.rollback()

                duplicate_refresh = await connection.begin_nested()
                try:
                    with pytest.raises(IntegrityError):
                        await connection.execute(
                            text(
                                "INSERT INTO refresh_tokens "
                                "(id, session_id, token_digest, key_version, state, expires_at) "
                                "VALUES (:id, :session_id, :digest, 1, 'active', "
                                "now() + interval '1 day')"
                            ),
                            {
                                "id": uuid4(),
                                "session_id": first_session_id,
                                "digest": b"c" * 32,
                            },
                        )
                finally:
                    await duplicate_refresh.rollback()

                cross_session = await connection.begin_nested()
                try:
                    cross_token_id = uuid4()
                    await connection.execute(
                        text(
                            "SET CONSTRAINTS "
                            "fk_refresh_tokens_replacement_same_session_refresh_tokens DEFERRED"
                        )
                    )
                    await connection.execute(
                        text(
                            "INSERT INTO refresh_tokens "
                            "(id, session_id, token_digest, key_version, state, expires_at) "
                            "VALUES (:id, :session_id, :digest, 1, 'active', "
                            "now() + interval '1 day')"
                        ),
                        {
                            "id": cross_token_id,
                            "session_id": second_session_id,
                            "digest": b"d" * 32,
                        },
                    )
                    await connection.execute(
                        text(
                            "UPDATE refresh_tokens SET state = 'consumed', consumed_at = now(), "
                            "replaced_by_id = :replacement_id WHERE id = :token_id"
                        ),
                        {"replacement_id": initial_token_id, "token_id": cross_token_id},
                    )
                    with pytest.raises(IntegrityError):
                        await connection.execute(
                            text(
                                "SET CONSTRAINTS "
                                "fk_refresh_tokens_replacement_same_session_refresh_tokens "
                                "IMMEDIATE"
                            )
                        )
                finally:
                    await cross_session.rollback()
            finally:
                await transaction.rollback()

    try:
        asyncio.run(assert_constraints())
    finally:
        asyncio.run(engine.dispose())
