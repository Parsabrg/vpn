"""Read-only database and migration-head readiness checks."""

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

# Keep this synchronized with the sole Alembic head. A migration test enforces it.
SCHEMA_HEAD = "20260720_0003"


async def schema_is_current(engine: AsyncEngine, *, expected_head: str = SCHEMA_HEAD) -> bool:
    """Return whether PostgreSQL is reachable and has exactly the expected head."""

    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
            revisions = await connection.execute(text("SELECT version_num FROM alembic_version"))
            return set(revisions.scalars()) == {expected_head}
    except SQLAlchemyError:
        return False
