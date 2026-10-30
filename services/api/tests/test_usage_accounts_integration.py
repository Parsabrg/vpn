"""Real-PostgreSQL proof that an allowance belongs to an account, not a device.

The unit tests drive scripted sessions, which answer whatever they are told;
they cannot show that the queries pick up every device an account has and
nothing another account has. This does, with two accounts on one server: A
with two devices, B with one.

- A's usage is the sum over both of A's devices, and none of B's.
- When A spends its allowance, both of A's devices lose their credentials and
  B's keeps its.

WireGuard peers stand in for every credential type: their counters are keyed
by the public key, which needs no key material to attribute, and enforcement
revokes all credential types through the same per-device call.
"""

import asyncio
import os
from typing import cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from test_provisioning_concurrency import AlwaysAllowingRedis, _fake_agent_builder, _key_material

from nebula_api.auth.redis_state import RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.provisioning.service import ProvisioningService
from nebula_api.settings import Settings
from nebula_api.topology_seed import (
    WIREGUARD_PROFILE_CODE,
    create_vpn_server,
    grant_user_server_access,
    seed_wireguard_protocol,
)
from nebula_api.usage.enforcement import enforce_traffic_quotas
from nebula_api.usage.service import UsageService, usage_digest

MEGABYTE = 1024**2


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_an_allowance_counts_and_cuts_off_every_device_of_one_account() -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])
    session_factory = create_session_factory(engine)
    keys = _key_material()
    provisioning = ProvisioningService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        Settings(env="test"),
        _fake_agent_builder(),
        keys,
    )
    usage = UsageService(session_factory, keys)

    unique = uuid4().hex[:12]
    server_code = f"quota-{unique}"
    account_a, account_b = uuid4(), uuid4()
    email_a = f"quota-a-{unique}@example.com"
    email_b = f"quota-b-{unique}@example.com"
    a_phone, a_laptop, b_phone = uuid4(), uuid4(), uuid4()
    peers = {
        # Not "A": that decodes to an all-zero key, which provisioning
        # refuses. And a letter whose low two bits are zero, as the last
        # character of a canonical 32-byte key must be.
        a_phone: ("I" * 43 + "=", 10 * MEGABYTE),
        a_laptop: ("M" * 43 + "=", 25 * MEGABYTE),
        b_phone: ("Q" * 43 + "=", 90 * MEGABYTE),
    }
    owners = {a_phone: account_a, a_laptop: account_a, b_phone: account_b}

    async def peer_states(device_ids: list[UUID]) -> list[str]:
        async with engine.begin() as connection:
            rows = await connection.execute(
                text("SELECT state FROM wireguard_peers WHERE device_id = ANY(:ids)"),
                {"ids": device_ids},
            )
            return [str(row[0]) for row in rows]

    async def scenario() -> None:
        await seed_wireguard_protocol(session_factory)
        await create_vpn_server(
            session_factory,
            code=server_code,
            display_name="Allowance Test VPS",
            agent_host=f"{server_code}.internal",
            agent_port=9443,
            public_host=f"{server_code}.internal",
            wireguard_client_pool="198.51.100.0/24",
            wireguard_gateway_address="198.51.100.1",
            maximum_devices=1000,
            state="active",
        )
        async with engine.begin() as connection:
            for user_id, email in ((account_a, email_a), (account_b, email_b)):
                await connection.execute(
                    text(
                        "INSERT INTO users "
                        "(id, email, email_normalized, password_hash, state, device_limit, "
                        "activated_at) VALUES "
                        "(:id, :email, :email, 'allowance-test-hash', 'active', 3, now())"
                    ),
                    {"id": user_id, "email": email},
                )
            for device_id, user_id in owners.items():
                await connection.execute(
                    text(
                        "INSERT INTO devices (id, user_id, name, platform, client_version) "
                        "VALUES (:id, :user_id, 'allowance-test-device', 'android', '1.0.0')"
                    ),
                    {"id": device_id, "user_id": user_id},
                )
        for email in (email_a, email_b):
            await grant_user_server_access(
                session_factory, user_email=email, server_code=server_code
            )

        try:
            for device_id, (public_key, _bytes) in peers.items():
                await provisioning.request_peer(
                    user_id=owners[device_id],
                    device_id=device_id,
                    server_code=server_code,
                    protocol_profile_code=WIREGUARD_PROFILE_CODE,
                    public_key=public_key,
                    network_prefix="198.51.100.0/24",
                    request_id=uuid4(),
                )
            async with engine.begin() as connection:
                for public_key, used in peers.values():
                    await connection.execute(
                        text(
                            "INSERT INTO credential_usage (id, protocol, identity, rx_bytes, "
                            "tx_bytes, last_rx_reading, last_tx_reading) VALUES "
                            "(:id, 'wireguard', :identity, :rx, 0, :rx, 0)"
                        ),
                        {"id": uuid4(), "identity": usage_digest(public_key), "rx": used},
                    )

            # Both of A's devices, and nothing of B's.
            a_usage = await usage.usage_for_user(account_a)
            assert a_usage.lifetime_bytes == 35 * MEGABYTE
            assert (await usage.usage_for_user(account_b)).lifetime_bytes == 90 * MEGABYTE

            # A: 30 MB from zero, and 35 MB used -- across two devices, neither
            # of which is over on its own. B: 30 MB granted after its 90 MB, so
            # nothing used on it yet.
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE users SET traffic_quota_bytes = :quota, "
                        "traffic_baseline_bytes = 0 WHERE id = ANY(:ids)"
                    ),
                    {"quota": 30 * MEGABYTE, "ids": [account_a]},
                )
                await connection.execute(
                    text(
                        "UPDATE users SET traffic_quota_bytes = :quota, "
                        "traffic_baseline_bytes = :baseline WHERE id = :id"
                    ),
                    {"quota": 30 * MEGABYTE, "baseline": 90 * MEGABYTE, "id": account_b},
                )

            summary = await enforce_traffic_quotas(session_factory, usage)

            assert account_a in summary.account_ids
            assert account_b not in summary.account_ids
            # Every device of the account that ran out, not only the one
            # that happened to be in use.
            assert await peer_states([a_phone, a_laptop]) == ["revoking", "revoking"]
            assert await peer_states([b_phone]) == ["active"]
            async with engine.begin() as connection:
                exhausted = await connection.execute(
                    text(
                        "SELECT id FROM users "
                        "WHERE id = ANY(:ids) AND quota_exhausted_at IS NOT NULL"
                    ),
                    {"ids": [account_a, account_b]},
                )
                assert [row[0] for row in exhausted] == [account_a]
        finally:
            device_ids = list(owners)
            user_ids = [account_a, account_b]
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM credential_usage WHERE identity = ANY(:identities)"),
                    {"identities": [usage_digest(key) for key, _ in peers.values()]},
                )
                await connection.execute(
                    text("DELETE FROM wireguard_peers WHERE device_id = ANY(:ids)"),
                    {"ids": device_ids},
                )
                await connection.execute(
                    text("DELETE FROM device_protocol_credentials WHERE device_id = ANY(:ids)"),
                    {"ids": device_ids},
                )
                server_id = await connection.scalar(
                    text("SELECT id FROM vpn_servers WHERE code = :code"), {"code": server_code}
                )
                await connection.execute(
                    text("DELETE FROM agent_operations WHERE vpn_server_id = :server_id"),
                    {"server_id": server_id},
                )
                await connection.execute(
                    text(
                        "DELETE FROM server_protocol_capabilities WHERE vpn_server_id = :server_id"
                    ),
                    {"server_id": server_id},
                )
                await connection.execute(
                    text("DELETE FROM user_protocol_permissions WHERE user_id = ANY(:ids)"),
                    {"ids": user_ids},
                )
                await connection.execute(
                    text("DELETE FROM user_server_assignments WHERE user_id = ANY(:ids)"),
                    {"ids": user_ids},
                )
                await connection.execute(
                    text("DELETE FROM devices WHERE id = ANY(:ids)"), {"ids": device_ids}
                )
                await connection.execute(
                    text("DELETE FROM vpn_servers WHERE id = :server_id"), {"server_id": server_id}
                )
                await connection.execute(
                    text("DELETE FROM users WHERE id = ANY(:ids)"), {"ids": user_ids}
                )

    try:
        asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())
