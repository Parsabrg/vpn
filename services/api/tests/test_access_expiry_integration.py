"""Real-PostgreSQL proof that lapsed access loses its credentials, and only it.

Five accounts on one server, each with a connected device. Four have lost
access in a different way since connecting; one has not, and carries an old
revoked assignment beside its active one -- the row a join would have matched,
cutting off somebody who still has access.
"""

import asyncio
import base64
import os
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import text
from test_provisioning_concurrency import AlwaysAllowingRedis, _fake_agent_builder, _key_material

from nebula_api.access.expiry import enforce_access_expiry
from nebula_api.auth.redis_state import RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.provisioning.revocation import credentials_awaiting_removal
from nebula_api.provisioning.service import ProvisioningService
from nebula_api.settings import Settings
from nebula_api.topology_seed import (
    WIREGUARD_PROFILE_CODE,
    create_vpn_server,
    grant_user_server_access,
    seed_wireguard_protocol,
)

# The last character of a canonical 32-byte key has its low two bits zero, and
# all-"A" is the all-zero key provisioning refuses.
_KEYS = {
    "healthy": "U" * 43 + "=",
    "expired_account": "Y" * 43 + "=",
    "expired_assignment": "c" * 43 + "=",
    "disabled_permission": "g" * 43 + "=",
    "revoked_device": "k" * 43 + "=",
}


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_only_access_that_lapsed_loses_its_credentials() -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])
    session_factory = create_session_factory(engine)
    provisioning = ProvisioningService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        Settings(env="test"),
        _fake_agent_builder(),
        _key_material(),
    )

    unique = uuid4().hex[:12]
    server_code = f"expiry-{unique}"
    users = {name: uuid4() for name in _KEYS}
    devices = {name: uuid4() for name in _KEYS}
    emails = {name: f"expiry-{index}-{unique}@example.com" for index, name in enumerate(_KEYS)}

    async def execute(sql: str, **params: object) -> None:
        async with engine.begin() as connection:
            await connection.execute(text(sql), params)

    async def peer_state(name: str) -> str:
        async with engine.begin() as connection:
            return str(
                await connection.scalar(
                    text("SELECT state FROM wireguard_peers WHERE device_id = :id"),
                    {"id": devices[name]},
                )
            )

    async def scenario() -> None:
        await seed_wireguard_protocol(session_factory)
        await create_vpn_server(
            session_factory,
            code=server_code,
            display_name="Expiry Test VPS",
            agent_host=f"{server_code}.internal",
            agent_port=9443,
            public_host=f"{server_code}.internal",
            wireguard_client_pool="192.0.2.0/24",
            wireguard_gateway_address="192.0.2.1",
            maximum_devices=1000,
            state="active",
        )
        for name in _KEYS:
            await execute(
                "INSERT INTO users (id, email, email_normalized, password_hash, state, "
                "device_limit, activated_at) VALUES "
                "(:id, :email, :email, 'expiry-test-hash', 'active', 3, now())",
                id=users[name],
                email=emails[name],
            )
            await execute(
                "INSERT INTO devices (id, user_id, name, platform, client_version) "
                "VALUES (:id, :user_id, 'expiry-test-device', 'android', '1.0.0')",
                id=devices[name],
                user_id=users[name],
            )
            await grant_user_server_access(
                session_factory, user_email=emails[name], server_code=server_code
            )

        try:
            for name, public_key in _KEYS.items():
                await provisioning.request_peer(
                    user_id=users[name],
                    device_id=devices[name],
                    server_code=server_code,
                    protocol_profile_code=WIREGUARD_PROFILE_CODE,
                    public_key=public_key,
                    network_prefix="192.0.2.0/24",
                    request_id=uuid4(),
                )

            # Connected, then access lapses in four different ways.
            await execute(
                "INSERT INTO user_server_assignments "
                "(id, user_id, vpn_server_id, state, assigned_at, revoked_at) "
                "SELECT :id, :user_id, id, 'revoked', now() - interval '2 days', "
                "now() - interval '1 day' FROM vpn_servers WHERE code = :code",
                id=uuid4(),
                user_id=users["healthy"],
                code=server_code,
            )
            await execute(
                "UPDATE users SET expires_at = now() - interval '1 minute' WHERE id = :id",
                id=users["expired_account"],
            )
            await execute(
                "UPDATE user_server_assignments SET assigned_at = now() - interval '2 hours', "
                "expires_at = now() - interval '1 hour' "
                "WHERE user_id = :id AND state = 'active'",
                id=users["expired_assignment"],
            )
            await execute(
                "UPDATE user_protocol_permissions SET state = 'disabled' WHERE user_id = :id",
                id=users["disabled_permission"],
            )
            await execute(
                "UPDATE devices SET state = 'revoked', revoked_at = now() WHERE id = :id",
                id=devices["revoked_device"],
            )

            summary = await enforce_access_expiry(session_factory)

            lapsed = {name for name in _KEYS if name != "healthy"}
            assert set(summary.account_ids) == {users[name] for name in lapsed}
            assert summary.credentials_revoked == len(lapsed)
            for name in lapsed:
                assert await peer_state(name) == "revoking", name
            assert await peer_state("healthy") == "active"
            assert await credentials_awaiting_removal(session_factory)

            # Nothing is revoked twice.
            again = await enforce_access_expiry(session_factory)
            assert again.credentials_revoked == 0
        finally:
            user_ids = list(users.values())
            device_ids = list(devices.values())
            await execute("DELETE FROM wireguard_peers WHERE device_id = ANY(:ids)", ids=device_ids)
            await execute(
                "DELETE FROM device_protocol_credentials WHERE device_id = ANY(:ids)",
                ids=device_ids,
            )
            async with engine.begin() as connection:
                server_id = await connection.scalar(
                    text("SELECT id FROM vpn_servers WHERE code = :code"), {"code": server_code}
                )
            await execute("DELETE FROM agent_operations WHERE vpn_server_id = :id", id=server_id)
            await execute(
                "DELETE FROM server_protocol_capabilities WHERE vpn_server_id = :id", id=server_id
            )
            await execute(
                "DELETE FROM user_protocol_permissions WHERE user_id = ANY(:ids)", ids=user_ids
            )
            await execute(
                "DELETE FROM user_server_assignments WHERE user_id = ANY(:ids)", ids=user_ids
            )
            await execute("DELETE FROM devices WHERE id = ANY(:ids)", ids=device_ids)
            await execute("DELETE FROM vpn_servers WHERE id = :id", id=server_id)
            await execute("DELETE FROM users WHERE id = ANY(:ids)", ids=user_ids)

    try:
        asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())


def test_the_fixture_keys_are_canonical() -> None:
    for key in _KEYS.values():
        assert base64.b64encode(base64.b64decode(key, validate=True)).decode() == key
    assert len(set(_KEYS.values())) == len(_KEYS)
