"""Real-PostgreSQL proof that concurrent WireGuard peer requests for the
same device are serialized into exactly one active peer.

Mirrors test_user_management_concurrency.py: races two independent
ProvisioningService.request_peer() calls against the same device+server and
relies on Phase A's row lock on the Device to serialize them -- the loser
sees the winner's just-committed peer and is rejected with
DeviceAlreadyHasPeer. Uses a fake agent client (no real WireGuard agent is
reachable in this test environment) to isolate the DB-level concurrency
guarantee from network behavior; topology setup reuses the same CLI seed
functions M4 already covers, incidentally proving they work against a real
database too.
"""

import asyncio
import os
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import text

from nebula_api.agent_client.client import AgentClient, AgentClientBuilder
from nebula_api.agent_client.models import ProvisionDeviceRequest, ProvisionDeviceResponse
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.provisioning.service import (
    DeviceAlreadyHasPeer,
    ProvisioningRejected,
    ProvisioningService,
)
from nebula_api.settings import Settings
from nebula_api.topology_seed import (
    create_vpn_server,
    grant_user_server_access,
    seed_wireguard_protocol,
)


class AlwaysAllowingRedis:
    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        del buckets, limit, window_seconds
        return True


class _FakeAgentClient:
    async def __aenter__(self) -> "_FakeAgentClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        return ProvisionDeviceResponse(
            state="active",
            applied_generation=request.desired_generation,
            server_public_key="B" * 43 + "=",
            listen_port=51820,
            public_endpoint="vps1.example.com:51820",
            client_dns="10.77.0.1",
            client_allowed_ips="0.0.0.0/0,::/0",
            persistent_keepalive_seconds=25,
        )


def _fake_agent_builder() -> AgentClientBuilder:
    def _builder(agent_host: str, agent_port: int) -> AgentClient:
        return cast(AgentClient, _FakeAgentClient())

    return _builder


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_concurrent_peer_requests_produce_exactly_one_active_peer() -> None:
    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = ProvisioningService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        Settings(env="test"),
        _fake_agent_builder(),
    )

    user_id = uuid4()
    device_id = uuid4()
    unique = uuid4().hex[:12]
    server_code = f"vps-{unique}"
    client_key = "E" * 43 + "="
    # grant_user_server_access() runs this through normalize_email(), which
    # rejects the reserved .test TLD -- unlike the other concurrency tests
    # here, which only ever insert their addresses via raw SQL.
    user_email = f"user-{unique}@example.com"

    async def scenario() -> tuple[int, int, int]:
        await seed_wireguard_protocol(session_factory)
        await create_vpn_server(
            session_factory,
            code=server_code,
            display_name="Concurrency Test VPS",
            agent_host=f"{server_code}.internal",
            agent_port=9443,
            public_host=f"{server_code}.internal",
            wireguard_client_pool="203.0.113.0/24",
            wireguard_gateway_address="203.0.113.1",
            maximum_devices=1000,
            state="active",
        )
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, email_normalized, password_hash, state, device_limit, "
                    "activated_at) VALUES "
                    "(:id, :email, :email, 'concurrency-test-hash', 'active', 3, now())"
                ),
                {"id": user_id, "email": user_email},
            )
            await connection.execute(
                text(
                    "INSERT INTO devices (id, user_id, name, platform, client_version) "
                    "VALUES (:id, :user_id, 'concurrency-test-device', 'android', '1.0.0')"
                ),
                {"id": device_id, "user_id": user_id},
            )
        await grant_user_server_access(
            session_factory,
            user_email=user_email,
            server_code=server_code,
        )

        try:
            results = await asyncio.gather(
                service.request_peer(
                    user_id=user_id,
                    device_id=device_id,
                    server_code=server_code,
                    public_key=client_key,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                service.request_peer(
                    user_id=user_id,
                    device_id=device_id,
                    server_code=server_code,
                    public_key=client_key,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                return_exceptions=True,
            )
            successes = [item for item in results if not isinstance(item, BaseException)]
            rejections = [item for item in results if isinstance(item, DeviceAlreadyHasPeer)]
            unexpected = [
                item
                for item in results
                if isinstance(item, BaseException) and not isinstance(item, DeviceAlreadyHasPeer)
            ]
            assert not unexpected, f"unexpected failures: {unexpected}"

            async with engine.begin() as connection:
                active_peer_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM wireguard_peers "
                        "WHERE device_id = :device_id AND state = 'active'"
                    ),
                    {"device_id": device_id},
                )
            return len(successes), len(rejections), cast(int, active_peer_count)
        finally:
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM wireguard_peers WHERE device_id = :device_id"),
                    {"device_id": device_id},
                )
                await connection.execute(
                    text("DELETE FROM device_protocol_credentials WHERE device_id = :device_id"),
                    {"device_id": device_id},
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
                    text("DELETE FROM user_protocol_permissions WHERE user_id = :user_id"),
                    {"user_id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM user_server_assignments WHERE user_id = :user_id"),
                    {"user_id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM devices WHERE id = :device_id"), {"device_id": device_id}
                )
                await connection.execute(
                    text("DELETE FROM vpn_servers WHERE id = :server_id"), {"server_id": server_id}
                )
                await connection.execute(
                    text("DELETE FROM users WHERE id = :user_id"), {"user_id": user_id}
                )

    try:
        successes, rejections, active_peer_count = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert successes == 1
    assert rejections == 1
    assert active_peer_count == 1


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_concurrent_requests_cannot_overshoot_the_server_device_cap() -> None:
    """Two *different* devices racing for a server's last free slot.

    The per-device row lock does not help here -- both devices are distinct,
    so only the per-server allocation advisory lock stops both requests from
    observing the same free slot and exceeding maximum_devices.
    """

    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    service = ProvisioningService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        Settings(env="test"),
        _fake_agent_builder(),
    )

    user_id = uuid4()
    first_device_id = uuid4()
    second_device_id = uuid4()
    unique = uuid4().hex[:12]
    server_code = f"cap-{unique}"
    user_email = f"capuser-{unique}@example.com"

    async def scenario() -> tuple[int, int, int]:
        await seed_wireguard_protocol(session_factory)
        await create_vpn_server(
            session_factory,
            code=server_code,
            display_name="Capacity Test VPS",
            agent_host=f"{server_code}.internal",
            agent_port=9443,
            public_host=f"{server_code}.internal",
            wireguard_client_pool="203.0.114.0/24",
            wireguard_gateway_address="203.0.114.1",
            maximum_devices=1,
            state="active",
        )
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, email_normalized, password_hash, state, device_limit, "
                    "activated_at) VALUES "
                    "(:id, :email, :email, 'capacity-test-hash', 'active', 5, now())"
                ),
                {"id": user_id, "email": user_email},
            )
            for device_id in (first_device_id, second_device_id):
                await connection.execute(
                    text(
                        "INSERT INTO devices (id, user_id, name, platform, client_version) "
                        "VALUES (:id, :user_id, 'capacity-test-device', 'android', '1.0.0')"
                    ),
                    {"id": device_id, "user_id": user_id},
                )
        await grant_user_server_access(
            session_factory, user_email=user_email, server_code=server_code
        )

        try:
            results = await asyncio.gather(
                *(
                    service.request_peer(
                        user_id=user_id,
                        device_id=device_id,
                        server_code=server_code,
                        public_key=key,
                        network_prefix="203.0.113.0/24",
                        request_id=uuid4(),
                    )
                    for device_id, key in (
                        (first_device_id, "G" * 43 + "="),
                        (second_device_id, "H" * 43 + "="),
                    )
                ),
                return_exceptions=True,
            )
            successes = [item for item in results if not isinstance(item, BaseException)]
            rejections = [item for item in results if isinstance(item, ProvisioningRejected)]
            unexpected = [
                item
                for item in results
                if isinstance(item, BaseException) and not isinstance(item, ProvisioningRejected)
            ]
            assert not unexpected, f"unexpected failures: {unexpected}"

            async with engine.begin() as connection:
                live_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM wireguard_peers p "
                        "JOIN vpn_servers s ON s.id = p.vpn_server_id "
                        "WHERE s.code = :code AND p.state IN "
                        "('requested', 'applying', 'active', 'revoking')"
                    ),
                    {"code": server_code},
                )
            return len(successes), len(rejections), cast(int, live_count)
        finally:
            async with engine.begin() as connection:
                server_id = await connection.scalar(
                    text("SELECT id FROM vpn_servers WHERE code = :code"), {"code": server_code}
                )
                await connection.execute(
                    text("DELETE FROM wireguard_peers WHERE vpn_server_id = :server_id"),
                    {"server_id": server_id},
                )
                await connection.execute(
                    text(
                        "DELETE FROM device_protocol_credentials WHERE vpn_server_id = :server_id"
                    ),
                    {"server_id": server_id},
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
                    text("DELETE FROM user_protocol_permissions WHERE user_id = :user_id"),
                    {"user_id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM user_server_assignments WHERE user_id = :user_id"),
                    {"user_id": user_id},
                )
                await connection.execute(
                    text("DELETE FROM devices WHERE user_id = :user_id"), {"user_id": user_id}
                )
                await connection.execute(
                    text("DELETE FROM vpn_servers WHERE id = :server_id"), {"server_id": server_id}
                )
                await connection.execute(
                    text("DELETE FROM users WHERE id = :user_id"), {"user_id": user_id}
                )

    try:
        successes, rejections, live_count = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert successes == 1
    assert rejections == 1
    assert live_count == 1
