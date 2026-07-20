import asyncio
import os
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError, SQLAlchemyError
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
