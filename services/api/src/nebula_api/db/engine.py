"""Async PostgreSQL engine and transaction-scoped session helpers."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

SessionFactory = async_sessionmaker[AsyncSession]


def create_database_engine(
    database_url: str,
    *,
    connect_timeout_seconds: int = 3,
    statement_timeout_ms: int = 5_000,
    echo: bool = False,
) -> AsyncEngine:
    """Create the application engine without connecting or mutating the schema."""

    url = make_url(database_url)
    if url.drivername != "postgresql+psycopg":
        raise ValueError("database URL must use the postgresql+psycopg driver")
    if connect_timeout_seconds < 1 or statement_timeout_ms < 1:
        raise ValueError("database timeouts must be positive")
    return create_async_engine(
        url,
        echo=echo,
        pool_pre_ping=True,
        pool_recycle=300,
        connect_args={
            "connect_timeout": connect_timeout_seconds,
            "options": f"-c statement_timeout={statement_timeout_ms}",
        },
    )


def create_session_factory(engine: AsyncEngine) -> SessionFactory:
    """Create sessions whose ORM state remains usable after a successful commit."""

    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def session_scope(session_factory: SessionFactory) -> AsyncIterator[AsyncSession]:
    """Commit one unit of work, rolling it back before propagating failures."""

    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
