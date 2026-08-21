"""Real-PostgreSQL proof that concurrent grant/assign calls are idempotent.

Mirrors `test_user_management_concurrency.py`, but proves the advisory-lock
choice in `AccessService` (rather than `.with_for_update()` alone) actually
matters: grant/assign may INSERT a row that doesn't exist yet, where a row
lock can't serialize two concurrent inserters racing the same unique
constraint / partial unique index.
"""

import asyncio
import os
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import text

from nebula_api.access.service import AccessService
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.settings import Settings


class AlwaysAllowingRedis:
    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        del buckets, limit, window_seconds
        return True


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_concurrent_grants_produce_exactly_one_permission_row_and_audit_event() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = AccessService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        Settings(env="test"),
    )

    admin_id = uuid4()
    user_id = uuid4()
    protocol_id = uuid4()
    profile_id = uuid4()
    unique = uuid4().hex[:12]

    async def scenario() -> tuple[int, int]:
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
            existing_protocol_id = await connection.scalar(
                text("SELECT id FROM protocols WHERE code = 'vless'")
            )
            if existing_protocol_id is None:
                await connection.execute(
                    text(
                        "INSERT INTO protocols (id, code, display_name, engine) VALUES "
                        "(:id, 'vless', 'VLESS', 'xray')"
                    ),
                    {"id": protocol_id},
                )
                existing_protocol_id = protocol_id
            await connection.execute(
                text(
                    "INSERT INTO protocol_profiles "
                    "(id, protocol_id, code, version, display_name, state, template_key) "
                    "VALUES (:id, :protocol_id, :code, 1, 'Test Profile', 'implemented', :key)"
                ),
                {
                    "id": profile_id,
                    "protocol_id": existing_protocol_id,
                    "code": f"test-profile-{unique}",
                    "key": f"test-profile-{unique}",
                },
            )

        try:
            results = await asyncio.gather(
                service.grant_permission(
                    user_id=user_id,
                    protocol_profile_id=profile_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                service.grant_permission(
                    user_id=user_id,
                    protocol_profile_id=profile_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
            )
            assert {result.state for result in results} == {"enabled"}

            async with engine.begin() as connection:
                permission_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM user_protocol_permissions "
                        "WHERE user_id = :user_id AND protocol_profile_id = :profile_id"
                    ),
                    {"user_id": user_id, "profile_id": profile_id},
                )
                audit_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM audit_logs WHERE target_kind = 'permission' "
                        "AND reason_code = 'granted' AND actor_id = :admin_id"
                    ),
                    {"admin_id": admin_id},
                )
            return cast(int, permission_count), cast(int, audit_count)
        finally:
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM user_protocol_permissions WHERE user_id = :id"),
                    {"id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM audit_logs WHERE actor_id = :id"), {"id": admin_id}
                )
                await connection.execute(
                    text("DELETE FROM protocol_profiles WHERE id = :id"), {"id": profile_id}
                )
                await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
                await connection.execute(
                    text("DELETE FROM admin_users WHERE id = :id"), {"id": admin_id}
                )

    try:
        permission_count, audit_count = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert permission_count == 1
    assert audit_count == 1


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_concurrent_assigns_produce_exactly_one_active_assignment_row() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = AccessService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        Settings(env="test"),
    )

    admin_id = uuid4()
    user_id = uuid4()
    server_id = uuid4()
    unique = uuid4().hex[:12]

    async def scenario() -> tuple[int, int]:
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
            await connection.execute(
                text(
                    "INSERT INTO vpn_servers "
                    "(id, code, display_name, state, agent_host, agent_port, public_host, "
                    "maximum_devices) VALUES "
                    "(:id, :code, 'Test Server', 'active', :host, 9443, :host, 1000)"
                ),
                {
                    "id": server_id,
                    "code": f"test-server-{unique}",
                    "host": f"test-server-{unique}.example.test",
                },
            )

        try:
            results = await asyncio.gather(
                service.assign_server(
                    user_id=user_id,
                    vpn_server_id=server_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                service.assign_server(
                    user_id=user_id,
                    vpn_server_id=server_id,
                    admin_id=admin_id,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
            )
            assert {result.state for result in results} == {"active"}

            async with engine.begin() as connection:
                assignment_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM user_server_assignments "
                        "WHERE user_id = :user_id AND vpn_server_id = :server_id "
                        "AND state = 'active'"
                    ),
                    {"user_id": user_id, "server_id": server_id},
                )
                audit_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM audit_logs WHERE target_kind = 'assignment' "
                        "AND reason_code = 'assigned' AND actor_id = :admin_id"
                    ),
                    {"admin_id": admin_id},
                )
            return cast(int, assignment_count), cast(int, audit_count)
        finally:
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM user_server_assignments WHERE user_id = :id"),
                    {"id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM audit_logs WHERE actor_id = :id"), {"id": admin_id}
                )
                await connection.execute(
                    text("DELETE FROM vpn_servers WHERE id = :id"), {"id": server_id}
                )
                await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
                await connection.execute(
                    text("DELETE FROM admin_users WHERE id = :id"), {"id": admin_id}
                )

    try:
        assignment_count, audit_count = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert assignment_count == 1
    assert audit_count == 1
