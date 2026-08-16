"""Real-PostgreSQL proof that concurrent disable/revoke calls are idempotent.

Mirrors `test_account_request_concurrency.py`: races two independent sessions
against `UserManagementService.disable_user()` for the same user and asserts
row-locking serializes them into exactly one terminal-state audit event.
"""

import asyncio
import os
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import text

from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.settings import Settings
from nebula_api.user_management.service import UserManagementService


class AlwaysAllowingRedis:
    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        del buckets, limit, window_seconds
        return True


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_concurrent_disables_produce_exactly_one_terminal_state() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = UserManagementService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        Settings(env="test"),
    )

    admin_id = uuid4()
    user_id = uuid4()
    unique = uuid4().hex[:12]

    async def scenario() -> tuple[str, int]:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO admin_users "
                    "(id, email, email_normalized, password_hash, role, state) VALUES "
                    "(:id, :email, :email, 'concurrency-test-hash', 'owner', 'active')"
                ),
                {"id": admin_id, "email": f"reviewer-{unique}@example.test"},
            )
            await connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, email_normalized, password_hash, state, device_limit, "
                    "activated_at) VALUES "
                    "(:id, :email, :email, 'concurrency-test-hash', 'active', 3, now())"
                ),
                {"id": user_id, "email": f"user-{unique}@example.test"},
            )

        try:
            results = await asyncio.gather(
                service.disable_user(
                    user_id=user_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                service.disable_user(
                    user_id=user_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
            )
            assert {result.state.value for result in results} == {"disabled"}

            async with engine.begin() as connection:
                state = await connection.scalar(
                    text("SELECT state FROM users WHERE id = :id"), {"id": user_id}
                )
                audit_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM audit_logs WHERE target_id = :id "
                        "AND target_kind = 'user' AND reason_code = 'disabled'"
                    ),
                    {"id": user_id},
                )
            return cast(str, state), cast(int, audit_count)
        finally:
            async with engine.begin() as connection:
                await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
                await connection.execute(
                    text("DELETE FROM admin_users WHERE id = :id"), {"id": admin_id}
                )

    try:
        state, audit_count = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert state == "disabled"
    assert audit_count == 1
