import asyncio
import os
from datetime import timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from redis.asyncio import Redis

from nebula_api.auth.redis_state import RateBucket, RedisAuthState, RedisClient

REDIS_URL_ENV = "NEBULA_REDIS_URL"
ADMIN_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


async def exercise_real_redis(redis_url: str) -> None:
    client = Redis.from_url(redis_url)
    prefix = f"nebula:test:auth:{uuid4().hex}"
    state = RedisAuthState(
        cast(RedisClient, client),
        key_ring={1: b"integration-test-pepper-value-01"},
        current_key_version=1,
        prefix=prefix,
    )
    try:
        bucket = RateBucket("user-login-network", "203.0.113.0/24")
        assert await state.rate_limit([bucket], limit=2, window_seconds=60)
        assert await state.rate_limit([bucket], limit=2, window_seconds=60)
        assert not await state.rate_limit([bucket], limit=2, window_seconds=60)
        assert await state.rate_limit(
            [RateBucket("admin-mfa-network", "203.0.113.0/24")],
            limit=2,
            window_seconds=60,
        )

        first_failure = await state.record_admin_failure(
            "owner@example.test",
            threshold=2,
            lock_seconds=60,
        )
        second_failure = await state.record_admin_failure(
            "owner@example.test",
            threshold=2,
            lock_seconds=60,
        )
        assert not first_failure.locked
        assert second_failure.locked
        assert (await state.lockout_status("owner@example.test")).locked
        await state.clear_admin_failures("owner@example.test")
        assert not (await state.lockout_status("owner@example.test")).locked

        challenge = await state.issue_preauth(
            admin_id=ADMIN_ID,
            purpose="login",
            context="203.0.113.0/24",
            ttl_seconds=60,
        )
        assert (
            await state.consume_preauth(
                challenge.token,
                purpose="login",
                context="198.51.100.0/24",
            )
            is None
        )
        consumed = await state.consume_preauth(
            challenge.token,
            purpose="login",
            context="203.0.113.0/24",
        )
        assert consumed is not None and consumed.admin_id == ADMIN_ID
        assert (
            await state.consume_preauth(
                challenge.token,
                purpose="login",
                context="203.0.113.0/24",
            )
            is None
        )

        issued = await state.issue_admin_session(
            admin_id=ADMIN_ID,
            mfa_method="totp",
            idle_ttl=timedelta(minutes=5),
            absolute_ttl=timedelta(hours=1),
        )
        assert (
            await state.get_admin_session(
                issued.session_token,
                idle_ttl=timedelta(minutes=5),
            )
        ) is not None
        replacement_csrf = await state.validate_and_rotate_csrf(
            issued.session_token,
            issued.csrf_token,
            idle_ttl=timedelta(minutes=5),
        )
        assert replacement_csrf is not None
        assert (
            await state.validate_and_rotate_csrf(
                issued.session_token,
                issued.csrf_token,
                idle_ttl=timedelta(minutes=5),
            )
            is None
        )

        rotated = await state.rotate_admin_session(
            issued.session_token,
            idle_ttl=timedelta(minutes=5),
            stepped_up=True,
        )
        assert rotated is not None and rotated.record.step_up_at is not None
        assert (
            await state.get_admin_session(
                issued.session_token,
                idle_ttl=timedelta(minutes=5),
            )
            is None
        )
        await state.revoke_admin_session(rotated.session_token)
        assert (
            await state.get_admin_session(
                rotated.session_token,
                idle_ttl=timedelta(minutes=5),
            )
            is None
        )
    finally:
        keys = [key async for key in client.scan_iter(match=f"{prefix}:*")]
        if keys:
            await client.delete(*keys)
        await client.aclose()


@pytest.mark.skipif(
    REDIS_URL_ENV not in os.environ,
    reason="real Redis integration is enabled in CI",
)
def test_atomic_auth_state_against_real_redis() -> None:
    redis_url = os.environ.get(REDIS_URL_ENV)
    assert redis_url is not None
    asyncio.run(exercise_real_redis(redis_url))
