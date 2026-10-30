"""Only enabled Xray capabilities select listener probes, once per node."""

import asyncio
import os
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from nebula_api.agent_client.client import AgentClient
from nebula_api.agent_client.models import XrayHealthRequest, XrayHealthResponse
from nebula_api.db.engine import create_database_engine
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ServerProtocolCapability,
    VPNServer,
)
from nebula_api.topology_admin.service import TopologyAdminService


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
@pytest.mark.parametrize("server_state", ["active", "maintenance", "disabled"])
def test_xray_capability_selection_is_distinct_and_keeps_inactive_nodes_visible(
    server_state: str,
) -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])
    unique = uuid4().hex[:12]
    calls: list[str] = []

    class Agent:
        async def __aenter__(self) -> "Agent":
            return self

        async def __aexit__(self, *_exc_info: object) -> None:
            pass

        async def xray_health(self, request: XrayHealthRequest) -> XrayHealthResponse:
            assert request.correlation_id is not None
            return XrayHealthResponse(
                state="healthy",
                observed_at=datetime.now(UTC),
                agent_version="1.0.0",
                listener_up=True,
                client_count=0,
            )

    def builder(host: str, port: int) -> AgentClient:
        assert port == 9443
        calls.append(host)
        return cast(AgentClient, Agent())

    async def scenario() -> None:
        try:
            async with engine.connect() as connection, connection.begin() as transaction:
                factory = async_sessionmaker(
                    connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
                )
                servers = [
                    VPNServer(
                        id=uuid4(),
                        code=f"xray-{unique}-{index}",
                        display_name="Test node",
                        state=server_state,
                        agent_host=f"xray-{unique}-{index}.internal",
                        agent_port=9443,
                        public_host="vpn.example.test",
                        maximum_devices=100,
                    )
                    for index in range(3)
                ]
                async with factory() as session:
                    session.add_all(servers)
                    await session.flush()
                    for code, engine_name in (("vless", "xray"), ("hysteria2", "hysteria")):
                        protocol = await session.scalar(
                            select(Protocol).where(Protocol.code == code)
                        )
                        if protocol is None:
                            protocol = Protocol(code=code, display_name=code, engine=engine_name)
                            session.add(protocol)
                            await session.flush()
                        for index in range(2 if code == "vless" else 1):
                            profile = ProtocolProfile(
                                id=uuid4(),
                                protocol_id=protocol.id,
                                code=f"xray-{unique}-{code}-{index}",
                                display_name=code,
                                version=1,
                                state="implemented",
                                template_key=f"test-{unique}-{code}-{index}",
                            )
                            session.add(profile)
                            await session.flush()
                            enabled_node = servers[0] if code == "vless" else servers[2]
                            session.add(
                                ServerProtocolCapability(
                                    vpn_server_id=enabled_node.id,
                                    protocol_profile_id=profile.id,
                                    state="enabled",
                                )
                            )
                            if code == "vless":
                                session.add(
                                    ServerProtocolCapability(
                                        vpn_server_id=servers[1].id,
                                        protocol_profile_id=profile.id,
                                        state="disabled",
                                    )
                                )
                        await session.flush()
                    await session.commit()

                entries = await TopologyAdminService(
                    factory, agent_client_builder=builder
                ).get_vpn_server_xray_health()
                own_entries = [
                    entry for entry in entries if entry.code.startswith(f"xray-{unique}-")
                ]
                assert [entry.server_id for entry in own_entries] == [servers[0].id]
                assert [host for host in calls if unique in host] == [servers[0].agent_host]
                assert own_entries[0].listener_up is True
                await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
