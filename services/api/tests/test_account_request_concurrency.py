"""Real-PostgreSQL proof that concurrent approvals serialize to one outcome.

Unlike the scripted-session unit tests in `test_account_request_service.py`,
this exercises genuine contention: two independent database sessions race
`AccountRequestService.approve()` against the same `AccountRequest` row and
the test asserts row-locking (`SELECT ... FOR UPDATE`) serializes them into
exactly one `User` and one active `UserActivation`, per the Phase 1.4
concurrent-approval requirement in `docs/phase-1-plan.md`.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from nebula_api.accounts.email_outbox import EmailOutboxRedisClient
from nebula_api.accounts.service import AccountRequestService
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.settings import Settings


class AlwaysAllowingRedis:
    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        del buckets, limit, window_seconds
        return True


class DiscardingOutboxClient:
    async def set(self, name: str, value: str, *, ex: int, nx: bool) -> object:
        del name, value, ex, nx
        return True


def _keys() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32})


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_concurrent_approvals_create_exactly_one_user_and_activation() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = AccountRequestService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        cast(EmailOutboxRedisClient, DiscardingOutboxClient()),
        _keys(),
        Settings(env="test"),
    )

    admin_id = uuid4()
    account_request_id = uuid4()
    now = datetime.now(UTC)
    unique = uuid4().hex[:12]

    async def scenario() -> tuple[int, int, int]:
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
                    "INSERT INTO account_requests "
                    "(id, email, email_normalized, state, expires_at) VALUES "
                    "(:id, :email, :email, 'pending', :expires_at)"
                ),
                {
                    "id": account_request_id,
                    "email": f"applicant-{unique}@example.test",
                    "expires_at": now + timedelta(days=7),
                },
            )

        try:
            results = await asyncio.gather(
                service.approve(
                    account_request_id=account_request_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                service.approve(
                    account_request_id=account_request_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
            )
            assert results[0].id == results[1].id == account_request_id
            assert {result.state.value for result in results} == {"approved"}

            async with engine.begin() as connection:
                user_id = await connection.scalar(
                    text("SELECT user_id FROM account_requests WHERE id = :id"),
                    {"id": account_request_id},
                )
                assert user_id is not None
                user_count = await connection.scalar(
                    text("SELECT count(*) FROM users WHERE id = :id"), {"id": user_id}
                )
                activation_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM user_activations "
                        "WHERE account_request_id = :id AND state = 'active'"
                    ),
                    {"id": account_request_id},
                )
                delivery_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM email_deliveries "
                        "WHERE subject_id = :user_id AND template_code = 'user_activation'"
                    ),
                    {"user_id": user_id},
                )
            return cast(int, user_count), cast(int, activation_count), cast(int, delivery_count)
        finally:
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "DELETE FROM email_deliveries WHERE subject_id IN "
                        "(SELECT user_id FROM account_requests WHERE id = :id)"
                    ),
                    {"id": account_request_id},
                )
                await connection.execute(
                    text("DELETE FROM user_activations WHERE account_request_id = :id"),
                    {"id": account_request_id},
                )
                await connection.execute(
                    text("DELETE FROM account_request_events WHERE request_id = :id"),
                    {"id": account_request_id},
                )
                user_id_to_delete = await connection.scalar(
                    text("SELECT user_id FROM account_requests WHERE id = :id"),
                    {"id": account_request_id},
                )
                await connection.execute(
                    text("DELETE FROM account_requests WHERE id = :id"),
                    {"id": account_request_id},
                )
                if user_id_to_delete is not None:
                    await connection.execute(
                        text("DELETE FROM users WHERE id = :id"), {"id": user_id_to_delete}
                    )
                await connection.execute(
                    text("DELETE FROM admin_users WHERE id = :id"), {"id": admin_id}
                )

    try:
        user_count, activation_count, delivery_count = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert user_count == 1
    assert activation_count == 1
    assert delivery_count == 1
