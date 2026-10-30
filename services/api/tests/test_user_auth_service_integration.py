"""Real-PostgreSQL + real-Redis proof that `UserAuthService.login()` actually
persists a session and refresh token together.

Regression coverage: `login()` used to `session.add_all((user_session,
refresh_record))` in one call. There is no ORM `relationship()` between
`UserSession` and `RefreshToken`, so the unit of work did not guarantee
`user_sessions` flushed before `refresh_tokens`, and the foreign key
sometimes rejected the reverse order -- confirmed against a real deployment,
where every real user login failed with an unhandled
`IntegrityError(ForeignKeyViolation)`. Every other login test in this repo
uses a hand-rolled fake session with no real foreign-key enforcement, so none
of them could have caught this.
"""

import asyncio
import os
from typing import cast
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from redis.asyncio import Redis
from sqlalchemy import text

from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RedisAuthState, RedisClient
from nebula_api.auth.user_service import UserAuthService
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.models.types import DevicePlatform
from nebula_api.passwords import hash_password
from nebula_api.settings import Settings

_DATABASE_URL_ENV = "NEBULA_DATABASE_URL"
_REDIS_URL_ENV = "NEBULA_REDIS_URL"
_PASSWORD = "correct-password-canary"  # noqa: S105 - test fixture


async def exercise_real_login(database_url: str, redis_url: str) -> None:
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    redis_client = Redis.from_url(redis_url)
    redis_prefix = f"nebula:test:user-auth:{uuid4().hex}"
    private_key = Ed25519PrivateKey.generate()
    key_material = AuthKeyMaterial(
        private_key,
        {"v1": private_key.public_key()},
        {1: b"p" * 32},
        {1: b"m" * 32},
        {1: b"x" * 32},
    )
    redis_state = RedisAuthState(
        cast(RedisClient, redis_client),
        key_ring={1: b"integration-test-pepper-value-01"},
        current_key_version=1,
        prefix=redis_prefix,
    )
    service = UserAuthService(session_factory, redis_state, key_material, Settings(env="test"))

    unique = uuid4().hex[:12]
    user_id = uuid4()
    # login() re-validates the identifier through normalize_email(), which
    # (unlike this repo's other integration tests, which only insert an
    # email and never revalidate it) rejects the .test TLD as a reserved
    # special-use domain even with check_deliverability=False --
    # example.com works fine since only the TLD is rejected, not this
    # specific second-level domain.
    email = f"user-{unique}@example.com"
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO users "
                "(id, email, email_normalized, password_hash, state, device_limit, "
                "activated_at) VALUES "
                "(:id, :email, :email, :password_hash, 'active', 3, now())"
            ),
            {"id": user_id, "email": email, "password_hash": hash_password(_PASSWORD)},
        )

    try:
        result = await service.login(
            identifier=email,
            password=_PASSWORD,
            device_id=None,
            device_name="integration-test-device",
            platform=DevicePlatform.ANDROID,
            client_version="1.0.0",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
        assert result.access_token
        assert result.refresh_token
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "DELETE FROM refresh_tokens WHERE session_id IN "
                    "(SELECT id FROM user_sessions WHERE user_id = :id)"
                ),
                {"id": user_id},
            )
            await connection.execute(
                text("DELETE FROM user_sessions WHERE user_id = :id"), {"id": user_id}
            )
            await connection.execute(
                text("DELETE FROM devices WHERE user_id = :id"), {"id": user_id}
            )
            # audit_logs is intentionally append-only -- the app's own DML
            # role cannot DELETE/UPDATE it, so its one row from this test
            # (login()'s "user_authenticated" event) is left in place rather
            # than cleaned up, same as other integration tests in this repo.
            await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        keys = [key async for key in redis_client.scan_iter(match=f"{redis_prefix}:*")]
        if keys:
            await redis_client.delete(*keys)
        await redis_client.aclose()
        await engine.dispose()


@pytest.mark.skipif(
    _DATABASE_URL_ENV not in os.environ or _REDIS_URL_ENV not in os.environ,
    reason="real PostgreSQL and Redis integration is enabled in CI",
)
def test_login_persists_session_and_refresh_token_against_real_postgres() -> None:
    database_url = os.environ[_DATABASE_URL_ENV]
    redis_url = os.environ[_REDIS_URL_ENV]
    asyncio.run(exercise_real_login(database_url, redis_url))
