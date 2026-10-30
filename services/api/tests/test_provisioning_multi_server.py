"""Real-PostgreSQL proof that a device holds its own credential on each server.

With a second server, a request to it found the device's live client on the
first server (the lookup and the live-uniqueness indexes named the device and
profile, not the server), reused it, provisioned it on the second server's
agent and left it filed under the first. The app then read "Your access to
this server has ended" (phone, 2026-10-30).
"""

import asyncio
import os
from typing import Any, cast
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from nebula_api.agent_client.client import AgentClient, AgentClientBuilder
from nebula_api.agent_client.models import (
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ProvisionXrayClientRequest,
    ProvisionXrayClientResponse,
)
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.provisioning.service import ProvisioningService
from nebula_api.settings import Settings
from nebula_api.topology_seed import (
    WIREGUARD_PROFILE_CODE,
    create_vpn_server,
    enable_server_capability,
    grant_user_server_access,
    seed_vless_xhttp_protocol,
    seed_wireguard_protocol,
)

XHTTP = "vless-xhttp-tls"


class _AllowAll:
    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        del buckets, limit, window_seconds
        return True


def _key_material() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(
        private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32}, {1: b"x" * 32}
    )


class _Agent:
    def __init__(self, host: str, calls: list[str]) -> None:
        self._host = host
        self._calls = calls

    async def __aenter__(self) -> "_Agent":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        self._calls.append(self._host)
        return ProvisionDeviceResponse(
            state="active",
            applied_generation=request.desired_generation,
            error_code=None,
            server_public_key="B" * 43 + "=",
            listen_port=51820,
            public_endpoint=f"{self._host}:51820",
            client_dns="10.77.0.1",
            client_allowed_ips="0.0.0.0/0,::/0",
            persistent_keepalive_seconds=25,
        )

    async def provision_xray_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        self._calls.append(self._host)
        return ProvisionXrayClientResponse(
            state="active",
            applied_generation=request.desired_generation,
            server_address=self._host,
            port=8445,
            sni=self._host,
            transport="xhttp",
            transport_security="tls",
            path="/xhttp",
        )


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_a_device_holds_its_own_credential_on_each_server() -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])
    session_factory = create_session_factory(engine)
    calls: list[str] = []

    def builder(agent_host: str, agent_port: int) -> AgentClient:
        return cast(AgentClient, _Agent(agent_host, calls))

    service = ProvisioningService(
        session_factory,
        cast(RedisAuthState, _AllowAll()),
        Settings(env="test"),
        cast(AgentClientBuilder, builder),
        _key_material(),
    )
    unique = uuid4().hex[:10]
    servers = {"a": f"multi-a-{unique}", "b": f"multi-b-{unique}"}
    user_id, device_id = uuid4(), uuid4()
    email = f"multi-{unique}@example.com"
    public_key = "M" * 43 + "="

    async def scenario() -> dict[str, Any]:
        await seed_wireguard_protocol(session_factory)
        await seed_vless_xhttp_protocol(session_factory)
        for index, code in enumerate(servers.values()):
            await create_vpn_server(
                session_factory,
                code=code,
                display_name=code,
                agent_host=f"{code}.internal",
                agent_port=9443,
                public_host=f"{code}.internal",
                wireguard_client_pool=f"203.0.{117 + index}.0/24",
                wireguard_gateway_address=f"203.0.{117 + index}.1",
                maximum_devices=1000,
                state="active",
            )
            await enable_server_capability(
                session_factory, server_code=code, protocol_profile_code=XHTTP
            )
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO users (id, email, email_normalized, password_hash, state, "
                    "device_limit, activated_at) VALUES "
                    "(:id, :email, :email, 'multi-test-hash', 'active', 5, now())"
                ),
                {"id": user_id, "email": email},
            )
            await connection.execute(
                text(
                    "INSERT INTO devices (id, user_id, name, platform, client_version) "
                    "VALUES (:id, :user_id, 'multi-test-device', 'android', '1.0.0')"
                ),
                {"id": device_id, "user_id": user_id},
            )
        for code in servers.values():
            await grant_user_server_access(session_factory, user_email=email, server_code=code)

        for code in servers.values():
            await service.request_peer(
                user_id=user_id,
                device_id=device_id,
                server_code=code,
                protocol_profile_code=WIREGUARD_PROFILE_CODE,
                public_key=public_key,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
            await service.request_xray_client(
                user_id=user_id,
                device_id=device_id,
                server_code=code,
                protocol_profile_code=XHTTP,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )

        async with engine.begin() as connection:
            peers = (
                (
                    await connection.execute(
                        text(
                            "SELECT s.code FROM wireguard_peers p JOIN vpn_servers s "
                            "ON s.id = p.vpn_server_id "
                            "WHERE p.device_id = :d AND p.state = 'active'"
                        ),
                        {"d": device_id},
                    )
                )
                .scalars()
                .all()
            )
            clients = (
                (
                    await connection.execute(
                        text(
                            "SELECT s.code FROM xray_clients x JOIN vpn_servers s "
                            "ON s.id = x.vpn_server_id "
                            "WHERE x.device_id = :d AND x.state = 'active'"
                        ),
                        {"d": device_id},
                    )
                )
                .scalars()
                .all()
            )
        return {"peers": sorted(peers), "clients": sorted(clients)}

    try:
        result = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert result["peers"] == sorted(servers.values())
    assert result["clients"] == sorted(servers.values())
    # Each server's agent got its own; none of server b's went to a's.
    assert calls.count(f"{servers['a']}.internal") == 2
    assert calls.count(f"{servers['b']}.internal") == 2
