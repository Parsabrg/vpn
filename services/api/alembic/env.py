"""Alembic environment for the asynchronous psycopg migration connection."""

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

import nebula_api.models  # noqa: F401  # Import all mapped tables for autogenerate.
from alembic import context
from nebula_api.db.base import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def migration_database_url() -> str:
    """Require an explicit migration credential rather than an application DSN."""

    database_url = os.environ.get("MIGRATION_DATABASE_URL")
    if not database_url:
        raise RuntimeError("MIGRATION_DATABASE_URL is required")
    if not database_url.startswith("postgresql+psycopg://"):
        raise RuntimeError("MIGRATION_DATABASE_URL must use postgresql+psycopg")
    return database_url


def configure_context(connection: object | None = None, *, url: str | None = None) -> None:
    """Apply deterministic comparison settings in online or offline mode."""

    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        transaction_per_migration=True,
        render_as_batch=False,
    )


def run_migrations_offline() -> None:
    configure_context(url=migration_database_url())
    with context.begin_transaction():
        context.run_migrations()


def run_sync_migrations(connection: object) -> None:
    configure_context(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = migration_database_url()
    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(run_sync_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
