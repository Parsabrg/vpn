import asyncio
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.db.engine import (
    SessionFactory,
    create_database_engine,
    create_session_factory,
    session_scope,
)


def test_engine_requires_async_psycopg_driver() -> None:
    with pytest.raises(ValueError, match=r"postgresql\+psycopg"):
        create_database_engine("sqlite+aiosqlite:///:memory:")


def test_engine_rejects_non_positive_timeouts() -> None:
    with pytest.raises(ValueError, match="timeouts"):
        create_database_engine(
            "postgresql+psycopg://app:secret@postgres/nebula",
            statement_timeout_ms=0,
        )


def test_engine_and_session_factory_do_not_connect_eagerly() -> None:
    engine = create_database_engine("postgresql+psycopg://app:secret@postgres/nebula")
    try:
        factory = create_session_factory(engine)
        assert factory.kw["expire_on_commit"] is False
        assert factory.kw["autoflush"] is False
        assert str(engine.url).endswith("@postgres/nebula")
        assert "secret" not in str(engine.url)
    finally:
        asyncio.run(engine.dispose())


def test_session_scope_commits_successful_unit_of_work() -> None:
    session = AsyncMock(spec=AsyncSession)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=context)

    async def run() -> None:
        async with session_scope(cast(SessionFactory, factory)) as yielded:
            assert yielded is session

    asyncio.run(run())
    session.commit.assert_awaited_once_with()
    session.rollback.assert_not_awaited()


def test_session_scope_rolls_back_failed_unit_of_work() -> None:
    session = AsyncMock(spec=AsyncSession)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=context)

    async def run() -> None:
        with pytest.raises(RuntimeError, match="failed"):
            async with session_scope(cast(SessionFactory, factory)):
                raise RuntimeError("failed")

    asyncio.run(run())
    session.rollback.assert_awaited_once_with()
    session.commit.assert_not_awaited()
