"""Minimal async PostgreSQL engine construction for the worker."""

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


def create_worker_engine(database_url: str) -> AsyncEngine:
    url = make_url(database_url)
    if url.drivername != "postgresql+psycopg":
        raise ValueError("database URL must use the postgresql+psycopg driver")
    return create_async_engine(url, pool_pre_ping=True, pool_recycle=300)
