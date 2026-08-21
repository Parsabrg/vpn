"""Real-PostgreSQL proof that `ServerDiscoveryService` implements the actual
eligibility join correctly: a server/profile is visible only when the
caller's own assignment, permission, and the server/capability rows are all
active -- and never leaks another user's assignment.
"""

import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import text

from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.servers.service import AvailableServerEntry, ServerDiscoveryService


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_visible_only_with_active_assignment_capability_and_permission() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = ServerDiscoveryService(session_factory)

    unique = uuid4().hex[:12]
    eligible_user_id = uuid4()
    other_user_id = uuid4()
    profile_id = uuid4()
    server_id = uuid4()

    async def scenario() -> tuple[list[AvailableServerEntry], list[AvailableServerEntry]]:
        async with engine.begin() as connection:
            for user_id in (eligible_user_id, other_user_id):
                await connection.execute(
                    text(
                        "INSERT INTO users "
                        "(id, email, email_normalized, password_hash, state, device_limit, "
                        "activated_at) VALUES "
                        "(:id, :email, :email, 'integration-test-hash', 'active', 3, now())"
                    ),
                    {"id": user_id, "email": f"user-{user_id.hex[:8]}-{unique}@example.test"},
                )
            # protocols.code is a closed vocabulary (CHECK ck_protocols_code_engine_pair
            # additionally pins 'wireguard' <-> 'native_wireguard' as a 1:1 singleton) --
            # it cannot be uniquified per test run. Reuse the shared 'vless'/'xray' row
            # instead (idempotent insert + lookup), which carries no such pairing.
            await connection.execute(
                text(
                    "INSERT INTO protocols (id, code, display_name, engine, is_user_selectable) "
                    "VALUES (:id, 'vless', 'VLESS', 'xray', true) "
                    "ON CONFLICT (code) DO NOTHING"
                ),
                {"id": uuid4()},
            )
            protocol_id = await connection.scalar(
                text("SELECT id FROM protocols WHERE code = 'vless'")
            )
            # protocol_profiles has a nulls-not-distinct unique constraint across
            # (protocol_id, transport, transport_security, flow, template_key,
            # template_version) -- since protocol_id is now the shared 'vless' row
            # reused across test runs, template_key must be set to something unique
            # per run or two rows with all-NULL tuple columns would collide.
            await connection.execute(
                text(
                    "INSERT INTO protocol_profiles "
                    "(id, protocol_id, code, version, display_name, state, requires_udp, "
                    "is_full_tunnel, template_key) VALUES "
                    "(:id, :protocol_id, :code, 1, 'Test profile', 'implemented', true, "
                    "true, :template_key)"
                ),
                {
                    "id": profile_id,
                    "protocol_id": protocol_id,
                    "code": f"profile-{unique}",
                    "template_key": f"test-{unique}",
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO vpn_servers "
                    "(id, code, display_name, state, agent_host, agent_port, public_host, "
                    "maximum_devices) VALUES "
                    "(:id, :code, 'Amsterdam 1', 'active', :agent_host, 9443, :public_host, "
                    "1000)"
                ),
                {
                    "id": server_id,
                    "code": f"ams-1-{unique}",
                    "agent_host": f"agent-{unique}.internal.test",
                    "public_host": f"ams-1-{unique}.example.test",
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO server_protocol_capabilities "
                    "(id, vpn_server_id, protocol_profile_id, state) VALUES "
                    "(:id, :server_id, :profile_id, 'enabled')"
                ),
                {"id": uuid4(), "server_id": server_id, "profile_id": profile_id},
            )
            await connection.execute(
                text(
                    "INSERT INTO user_server_assignments "
                    "(id, user_id, vpn_server_id, state, assigned_at) VALUES "
                    "(:id, :user_id, :server_id, 'active', now())"
                ),
                {"id": uuid4(), "user_id": eligible_user_id, "server_id": server_id},
            )
            await connection.execute(
                text(
                    "INSERT INTO user_protocol_permissions "
                    "(id, user_id, protocol_profile_id, state, granted_at) VALUES "
                    "(:id, :user_id, :profile_id, 'enabled', now())"
                ),
                {"id": uuid4(), "user_id": eligible_user_id, "profile_id": profile_id},
            )

        try:
            eligible_result = await service.list_available_servers(eligible_user_id)
            other_result = await service.list_available_servers(other_user_id)
            return list(eligible_result), list(other_result)
        finally:
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM user_protocol_permissions WHERE user_id = :id"),
                    {"id": eligible_user_id},
                )
                await connection.execute(
                    text("DELETE FROM user_server_assignments WHERE user_id = :id"),
                    {"id": eligible_user_id},
                )
                await connection.execute(
                    text("DELETE FROM server_protocol_capabilities WHERE vpn_server_id = :id"),
                    {"id": server_id},
                )
                await connection.execute(
                    text("DELETE FROM vpn_servers WHERE id = :id"), {"id": server_id}
                )
                await connection.execute(
                    text("DELETE FROM protocol_profiles WHERE id = :id"), {"id": profile_id}
                )
                # The shared 'vless' protocols row is intentionally left in place --
                # see the ON CONFLICT DO NOTHING insert above.
                await connection.execute(
                    text("DELETE FROM users WHERE id IN (:eligible, :other)"),
                    {"eligible": eligible_user_id, "other": other_user_id},
                )

    try:
        eligible_result, other_result = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert len(eligible_result) == 1
    assert eligible_result[0].code == f"ams-1-{unique}"
    assert len(eligible_result[0].profiles) == 1
    assert eligible_result[0].profiles[0].code == f"profile-{unique}"
    # A user with no assignment of their own must never see this server,
    # even though the server/capability/profile rows exist.
    assert other_result == []


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_disabled_permission_hides_an_otherwise_eligible_server() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = ServerDiscoveryService(session_factory)

    unique = uuid4().hex[:12]
    user_id = uuid4()
    profile_id = uuid4()
    server_id = uuid4()

    async def scenario() -> list[AvailableServerEntry]:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, email_normalized, password_hash, state, device_limit, "
                    "activated_at) VALUES "
                    "(:id, :email, :email, 'integration-test-hash', 'active', 3, now())"
                ),
                {"id": user_id, "email": f"user-{unique}@example.test"},
            )
            # See the sibling test above for why 'protocols' rows must reuse the
            # shared 'vless'/'xray' row rather than a per-test-run unique code.
            await connection.execute(
                text(
                    "INSERT INTO protocols (id, code, display_name, engine, is_user_selectable) "
                    "VALUES (:id, 'vless', 'VLESS', 'xray', true) "
                    "ON CONFLICT (code) DO NOTHING"
                ),
                {"id": uuid4()},
            )
            protocol_id = await connection.scalar(
                text("SELECT id FROM protocols WHERE code = 'vless'")
            )
            await connection.execute(
                text(
                    "INSERT INTO protocol_profiles "
                    "(id, protocol_id, code, version, display_name, state, requires_udp, "
                    "is_full_tunnel, template_key) VALUES "
                    "(:id, :protocol_id, :code, 1, 'Test profile', 'implemented', true, "
                    "true, :template_key)"
                ),
                {
                    "id": profile_id,
                    "protocol_id": protocol_id,
                    "code": f"profile-{unique}",
                    "template_key": f"test-{unique}",
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO vpn_servers "
                    "(id, code, display_name, state, agent_host, agent_port, public_host, "
                    "maximum_devices) VALUES "
                    "(:id, :code, 'Amsterdam 1', 'active', :agent_host, 9443, :public_host, "
                    "1000)"
                ),
                {
                    "id": server_id,
                    "code": f"ams-1-{unique}",
                    "agent_host": f"agent-{unique}.internal.test",
                    "public_host": f"ams-1-{unique}.example.test",
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO server_protocol_capabilities "
                    "(id, vpn_server_id, protocol_profile_id, state) VALUES "
                    "(:id, :server_id, :profile_id, 'enabled')"
                ),
                {"id": uuid4(), "server_id": server_id, "profile_id": profile_id},
            )
            await connection.execute(
                text(
                    "INSERT INTO user_server_assignments "
                    "(id, user_id, vpn_server_id, state, assigned_at) VALUES "
                    "(:id, :user_id, :server_id, 'active', now())"
                ),
                {"id": uuid4(), "user_id": user_id, "server_id": server_id},
            )
            # Deliberately 'disabled', unlike the happy-path test above.
            await connection.execute(
                text(
                    "INSERT INTO user_protocol_permissions "
                    "(id, user_id, protocol_profile_id, state, granted_at) VALUES "
                    "(:id, :user_id, :profile_id, 'disabled', now())"
                ),
                {"id": uuid4(), "user_id": user_id, "profile_id": profile_id},
            )

        try:
            return list(await service.list_available_servers(user_id))
        finally:
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM user_protocol_permissions WHERE user_id = :id"),
                    {"id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM user_server_assignments WHERE user_id = :id"),
                    {"id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM server_protocol_capabilities WHERE vpn_server_id = :id"),
                    {"id": server_id},
                )
                await connection.execute(
                    text("DELETE FROM vpn_servers WHERE id = :id"), {"id": server_id}
                )
                await connection.execute(
                    text("DELETE FROM protocol_profiles WHERE id = :id"), {"id": profile_id}
                )
                await connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})

    try:
        result = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert result == []
