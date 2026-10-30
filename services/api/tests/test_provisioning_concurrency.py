"""Real-PostgreSQL proof that concurrent WireGuard peer requests for the
same device are serialized into exactly one active peer.

Mirrors test_user_management_concurrency.py: races two independent
ProvisioningService.request_peer() calls against the same device+server and
relies on Phase A's row lock on the Device to serialize them -- the loser
sees the winner's just-committed peer, still mid-flight (state=applying,
since Phase C only settles it to active in a later transaction after the
agent call returns), and is rejected with OperationInProgress. A peer that
had already settled to active by the time a later request observes it would
instead be reconnected to, not rejected -- that path is covered by
test_provisioning_service.py's reconnect tests, not this race. Uses a fake
agent client (no real WireGuard agent is reachable in this test environment)
to isolate the DB-level concurrency guarantee from network behavior;
topology setup reuses the same CLI seed functions M4 already covers,
incidentally proving they work against a real database too.
"""

import asyncio
import os
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from nebula_api.agent_client.client import AgentClient, AgentClientBuilder
from nebula_api.agent_client.models import (
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
)
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.provisioning.service import (
    OperationInProgress,
    ProvisioningRejected,
    ProvisioningService,
)
from nebula_api.settings import Settings
from nebula_api.topology_seed import (
    WIREGUARD_PROFILE_CODE,
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
    def __init__(self, *, provision_state: str = "active") -> None:
        self._provision_state = provision_state

    async def __aenter__(self) -> "_FakeAgentClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        return ProvisionDeviceResponse(
            state=cast(Any, self._provision_state),
            applied_generation=request.desired_generation,
            error_code=None if self._provision_state == "active" else "agent_rejected",
            server_public_key="B" * 43 + "=",
            listen_port=51820,
            public_endpoint="vps1.example.com:51820",
            client_dns="10.77.0.1",
            client_allowed_ips="0.0.0.0/0,::/0",
            persistent_keepalive_seconds=25,
        )

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        return RevokeDeviceResponse(
            state="revoked",
            applied_generation=request.desired_generation,
            revoked_at=datetime.now(UTC),
        )


def _fake_agent_builder(*, provision_state: str = "active") -> AgentClientBuilder:
    def _builder(agent_host: str, agent_port: int) -> AgentClient:
        return cast(AgentClient, _FakeAgentClient(provision_state=provision_state))

    return _builder


def _key_material() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(
        private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32}, {1: b"x" * 32}
    )


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
        _key_material(),
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
                    protocol_profile_code=WIREGUARD_PROFILE_CODE,
                    public_key=client_key,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                service.request_peer(
                    user_id=user_id,
                    device_id=device_id,
                    server_code=server_code,
                    protocol_profile_code=WIREGUARD_PROFILE_CODE,
                    public_key=client_key,
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                ),
                return_exceptions=True,
            )
            successes = [item for item in results if not isinstance(item, BaseException)]
            rejections = [item for item in results if isinstance(item, OperationInProgress)]
            unexpected = [
                item
                for item in results
                if isinstance(item, BaseException) and not isinstance(item, OperationInProgress)
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

    # Both calls succeeding is correct, and so is one of them being rejected.
    # `request_peer` reuses an already-ACTIVE peer rather than refusing (see
    # "reconnect to an existing active WireGuard peer instead of rejecting" --
    # toggling the VPN off and on is normal usage the app cannot reliably
    # detect, since its local state does not survive a reinstall but the
    # server's does). So the outcome depends on interleaving: if the first
    # request reaches ACTIVE before the second reads, the second reconnects
    # and succeeds; if the second reads while the first is still in flight, it
    # sees a non-ACTIVE live peer and is rejected.
    #
    # Asserting one specific interleaving made this test fail on a behaviour
    # change that was deliberate, which is worse than not having it. The
    # invariant is what the test is named for and does not depend on ordering:
    # a device ends up with exactly one active peer, and nothing fails in a
    # way other than an orderly rejection.
    assert successes + rejections == 2
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
        _key_material(),
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
                        protocol_profile_code=WIREGUARD_PROFILE_CODE,
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


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_revoked_and_failed_peer_addresses_are_reused_by_a_later_request() -> None:
    """A live peer's address is excluded from allocation, but a revoked or
    failed one is not: `uq_wireguard_peers_server_address_live` only scopes
    uniqueness to live states, so once a peer leaves that set its address is
    free for a later, unrelated device to receive.
    """

    database_url = os.environ["NEBULA_DATABASE_URL"]
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    settings = Settings(env="test")
    succeeding_service = ProvisioningService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        settings,
        _fake_agent_builder(),
        _key_material(),
    )
    failing_service = ProvisioningService(
        session_factory,
        cast(RedisAuthState, AlwaysAllowingRedis()),
        settings,
        _fake_agent_builder(provision_state="failed"),
        _key_material(),
    )

    user_id = uuid4()
    device_ids = {name: uuid4() for name in "abcd"}
    unique = uuid4().hex[:12]
    server_code = f"reclaim-{unique}"
    user_email = f"reclaimuser-{unique}@example.com"
    public_keys = {
        "a": "I" * 43 + "=",
        "b": "J" * 43 + "=",
        "c": "K" * 43 + "=",
        "d": "L" * 43 + "=",
    }

    async def scenario() -> tuple[str, str]:
        await seed_wireguard_protocol(session_factory)
        await create_vpn_server(
            session_factory,
            code=server_code,
            display_name="Reclaim Test VPS",
            agent_host=f"{server_code}.internal",
            agent_port=9443,
            public_host=f"{server_code}.internal",
            wireguard_client_pool="203.0.116.0/24",
            wireguard_gateway_address="203.0.116.1",
            maximum_devices=1000,
            state="active",
        )
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO users "
                    "(id, email, email_normalized, password_hash, state, device_limit, "
                    "activated_at) VALUES "
                    "(:id, :email, :email, 'reclaim-test-hash', 'active', 5, now())"
                ),
                {"id": user_id, "email": user_email},
            )
            for device_id in device_ids.values():
                await connection.execute(
                    text(
                        "INSERT INTO devices (id, user_id, name, platform, client_version) "
                        "VALUES (:id, :user_id, 'reclaim-test-device', 'android', '1.0.0')"
                    ),
                    {"id": device_id, "user_id": user_id},
                )
        await grant_user_server_access(
            session_factory, user_email=user_email, server_code=server_code
        )

        try:
            peer_a = await succeeding_service.request_peer(
                user_id=user_id,
                device_id=device_ids["a"],
                server_code=server_code,
                protocol_profile_code=WIREGUARD_PROFILE_CODE,
                public_key=public_keys["a"],
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
            await succeeding_service.revoke_peer(
                user_id=user_id,
                device_id=device_ids["a"],
                server_code=server_code,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
            peer_b = await succeeding_service.request_peer(
                user_id=user_id,
                device_id=device_ids["b"],
                server_code=server_code,
                protocol_profile_code=WIREGUARD_PROFILE_CODE,
                public_key=public_keys["b"],
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )

            with pytest.raises(ProvisioningRejected):
                await failing_service.request_peer(
                    user_id=user_id,
                    device_id=device_ids["c"],
                    server_code=server_code,
                    protocol_profile_code=WIREGUARD_PROFILE_CODE,
                    public_key=public_keys["c"],
                    network_prefix="203.0.113.0/24",
                    request_id=uuid4(),
                )
            peer_d = await succeeding_service.request_peer(
                user_id=user_id,
                device_id=device_ids["d"],
                server_code=server_code,
                protocol_profile_code=WIREGUARD_PROFILE_CODE,
                public_key=public_keys["d"],
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )

            async with engine.begin() as connection:
                failed_address = await connection.scalar(
                    text(
                        "SELECT host(assigned_address) FROM wireguard_peers "
                        "WHERE device_id = :device_id AND state = 'failed'"
                    ),
                    {"device_id": device_ids["c"]},
                )
            assert peer_b.assigned_address == str(peer_a.assigned_address)
            assert peer_d.assigned_address == failed_address
            return peer_b.assigned_address, peer_d.assigned_address
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
        reused_address, reused_failed_address = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert reused_address == "203.0.116.2"
    assert reused_failed_address == "203.0.116.3"
