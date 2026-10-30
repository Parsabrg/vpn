"""Real SQL aggregation of unsettled runtime rows, without counting credentials twice."""

import asyncio
import base64
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from nebula_api.db.engine import create_database_engine
from nebula_api.models.identity import Device, User
from nebula_api.models.operations import (
    RECONCILIATION_OUTCOMES,
    AgentOperation,
    ReconciliationRecord,
)
from nebula_api.models.provisioning import DeviceProtocolCredential, WireGuardPeer, XrayClient
from nebula_api.models.topology import Protocol, ProtocolProfile, VPNServer
from nebula_api.provisioning.reconciliation import _record
from nebula_api.topology_admin.service import TopologyAdminService


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_reconciliation_counts_all_engines_and_clears_confirmed_removals() -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])

    async def scenario() -> None:
        try:
            async with engine.connect() as connection, connection.begin() as transaction:
                factory = async_sessionmaker(
                    connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
                )
                service = TopologyAdminService(factory)
                now = datetime.now(UTC)
                unique = uuid4().hex[:12]
                servers = [
                    VPNServer(
                        id=uuid4(),
                        code=f"summary-{unique}-{index}",
                        display_name="Test server",
                        agent_host=f"summary-{unique}-{index}.internal",
                        agent_port=9443,
                        public_host="vpn.example.test",
                        state=state,
                        maximum_devices=100,
                    )
                    for index, state in enumerate(("active", "maintenance", "disabled"))
                ]
                user = User(
                    id=uuid4(),
                    email=f"{unique}@example.test",
                    email_normalized=f"{unique}@example.test",
                    device_limit=100,
                )
                async with factory() as session:
                    session.add_all([user, *servers])
                    await session.flush()
                    for code, engine_name in (
                        ("wireguard", "native_wireguard"),
                        ("vless", "xray"),
                        ("hysteria2", "hysteria"),
                    ):
                        protocol = await session.scalar(
                            select(Protocol).where(Protocol.code == code)
                        )
                        if protocol is None:
                            protocol = Protocol(
                                code=code,
                                display_name=code,
                                engine=engine_name,
                            )
                            session.add(protocol)
                            await session.flush()
                        profile = ProtocolProfile(
                            id=uuid4(),
                            protocol_id=protocol.id,
                            code=f"summary-{code}-{unique}",
                            display_name=code,
                            version=1,
                            template_key=f"summary-{unique}-{code}",
                        )
                        session.add(profile)
                        await session.flush()
                        cases = [
                            (servers[0], state)
                            for state in (
                                "requested",
                                "applying",
                                "active",
                                "revoking",
                                "revoked",
                                "failed",
                            )
                        ]
                        if code != "wireguard":
                            cases.append((servers[1], "failed"))
                        for index, (server, state) in enumerate(cases):
                            device = Device(
                                id=uuid4(),
                                user_id=user.id,
                                name="Test",
                                platform="android",
                                client_version="1.0.0",
                            )
                            session.add(device)
                            await session.flush()
                            wireguard = code == "wireguard"
                            credential = DeviceProtocolCredential(
                                id=uuid4(),
                                device_id=device.id,
                                protocol_profile_id=profile.id,
                                vpn_server_id=server.id,
                                kind="wireguard_public" if wireguard else "xray_bearer",
                                state=state,
                                issued_at=now,
                                revoked_at=now if state == "revoked" else None,
                                ciphertext=None if wireguard else b"credential-canary",
                                nonce=None if wireguard else b"n" * 12,
                                key_version=None if wireguard else "v1",
                            )
                            session.add(credential)
                            await session.flush()
                            identity: dict[str, Any] = {
                                "credential_id": credential.id,
                                "device_id": device.id,
                                "protocol_profile_id": profile.id,
                                "vpn_server_id": server.id,
                                "state": state,
                                "revoked_at": now if state == "revoked" else None,
                            }
                            if wireguard:
                                session.add(
                                    WireGuardPeer(
                                        **identity,
                                        public_key=base64.b64encode(uuid4().bytes * 2).decode(),
                                        assigned_address=f"192.0.2.{index + 1}",
                                    )
                                )
                            else:
                                session.add(XrayClient(**identity, opaque_label=uuid4().hex))
                            await session.flush()
                    # A credential with no runtime row must not become a phantom runtime failure.
                    session.add(
                        DeviceProtocolCredential(
                            device_id=device.id,
                            protocol_profile_id=profile.id,
                            vpn_server_id=servers[1].id,
                            kind="xray_bearer",
                            state="failed",
                            issued_at=now,
                        )
                    )
                    await session.commit()

                entries = {
                    entry.server_id: entry
                    for entry in await service.get_vpn_server_reconciliation()
                }
                assert entries[servers[0].id].pending_provisions == 6
                assert entries[servers[0].id].pending_revocations == 3
                assert entries[servers[0].id].failed_records == 3
                for server in servers[1:]:
                    assert entries[server.id].pending_provisions == 0
                    assert entries[server.id].pending_revocations == 0
                assert entries[servers[1].id].failed_records == 2
                assert entries[servers[2].id].failed_records == 0
                assert [
                    entry.code for entry in await service.get_vpn_server_reconciliation()
                ] == sorted(entry.code for entry in entries.values())
                async with factory() as session:
                    for model in (WireGuardPeer, XrayClient, DeviceProtocolCredential):
                        await session.execute(
                            update(model)
                            .where(
                                model.vpn_server_id == servers[0].id,
                                model.state == "revoking",
                            )
                            .values(state="revoked", revoked_at=now)
                        )
                    await session.commit()
                entries = {
                    entry.server_id: entry
                    for entry in await service.get_vpn_server_reconciliation()
                }
                assert entries[servers[0].id].pending_revocations == 0
                await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
@pytest.mark.parametrize("target_kind", ["wireguard_peer", "xray_client"])
def test_recorded_repair_evidence_links_operation_and_reaches_history(target_kind: str) -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])

    async def scenario() -> None:
        try:
            async with engine.connect() as connection, connection.begin() as transaction:
                factory = async_sessionmaker(
                    connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
                )
                now = datetime.now(UTC)
                target_id = uuid4()
                unique = uuid4().hex[:12]
                server = VPNServer(
                    id=uuid4(),
                    code=f"evidence-{unique}",
                    display_name="Test server",
                    agent_host=f"evidence-{unique}.internal",
                    agent_port=9443,
                    public_host="vpn.example.test",
                    state="active",
                    maximum_devices=100,
                )
                operation = AgentOperation(
                    id=uuid4(),
                    vpn_server_id=server.id,
                    idempotency_key=uuid4(),
                    correlation_id=uuid4(),
                    operation_kind="revoke_device",
                    target_kind=target_kind,
                    target_id=target_id,
                    state="running",
                    desired_generation=1,
                    attempt_count=1,
                    request_fingerprint="f" * 64,
                    requested_at=now,
                    started_at=now,
                )
                async with factory() as session:
                    session.add(server)
                    await session.flush()
                    session.add(operation)
                    await session.commit()

                await _record(
                    factory,
                    server.id,
                    target_id,
                    1,
                    None,
                    "ambiguous",
                    target_kind,
                    agent_operation_id=operation.id,
                    error_code="agent_response_ambiguous",
                )
                async with factory() as session:
                    record = await session.scalar(
                        select(ReconciliationRecord).where(
                            ReconciliationRecord.target_id == target_id
                        )
                    )
                    assert record is not None
                    assert record.agent_operation_id == operation.id
                    persisted_operation = await session.get(AgentOperation, operation.id)
                    assert persisted_operation is not None
                    assert persisted_operation.state == "running"
                    assert persisted_operation.finished_at is None

                page = await TopologyAdminService(factory).list_reconciliation_history(
                    server_id=server.id,
                    target_id=target_id,
                    outcome="ambiguous",
                )
                assert page.total == 1
                entry = page.items[0]
                assert entry.outcome == "ambiguous"
                assert entry.error_code == "agent_response_ambiguous"
                assert entry.observed_generation is None
                assert entry.target_kind == target_kind
                await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_reconciliation_history_filters_and_pages_with_stable_timestamp_ties() -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])

    async def scenario() -> None:
        try:
            async with engine.connect() as connection, connection.begin() as transaction:
                factory = async_sessionmaker(
                    connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
                )
                service = TopologyAdminService(factory)
                now = datetime.now(UTC)
                unique = uuid4().hex[:12]
                servers = [
                    VPNServer(
                        id=uuid4(),
                        code=f"history-{unique}-{index}",
                        display_name="Test server",
                        agent_host=f"history-{unique}-{index}.internal",
                        agent_port=9443,
                        public_host="vpn.example.test",
                        state="disabled",
                    )
                    for index in range(2)
                ]
                targets = [uuid4(), uuid4()]
                records = [
                    ReconciliationRecord(
                        id=uuid4(),
                        vpn_server_id=servers[0].id,
                        target_kind="wireguard_peer" if index % 2 == 0 else "xray_client",
                        target_id=targets[index % 2],
                        desired_generation=index + 1,
                        observed_generation=0 if index == 0 else None,
                        checked_at=now + timedelta(seconds=index // 2),
                        outcome=outcome,
                        error_code="agent_unreachable" if outcome == "repair_failed" else None,
                    )
                    for index, outcome in enumerate(RECONCILIATION_OUTCOMES)
                ]
                async with factory() as session:
                    session.add_all(servers)
                    await session.flush()
                    session.add_all(records)
                    session.add(
                        ReconciliationRecord(
                            vpn_server_id=servers[1].id,
                            target_kind="wireguard_peer",
                            target_id=targets[0],
                            desired_generation=1,
                            outcome="repair_failed",
                            checked_at=now,
                        )
                    )
                    await session.commit()
                expected = sorted(records, key=lambda row: (row.checked_at, row.id), reverse=True)
                pages = [
                    await service.list_reconciliation_history(
                        server_id=servers[0].id,
                        limit=2,
                        offset=offset,
                    )
                    for offset in (0, 2, 4)
                ]
                assert all(page.total == 6 for page in pages)
                assert [entry.id for page in pages for entry in page.items] == [
                    row.id for row in expected
                ]
                assert pages[0].items[0].server_code == servers[0].code
                filtered = await service.list_reconciliation_history(
                    server_id=servers[0].id,
                    target_id=targets[0],
                    outcome="repair_failed",
                )
                assert filtered.total == 1
                assert filtered.items[0].error_code == "agent_unreachable"
                target_history = await service.list_reconciliation_history(
                    server_id=servers[0].id,
                    target_id=targets[0],
                )
                assert target_history.total == 3
                assert target_history.items[-1].observed_generation == 0
                empty = await service.list_reconciliation_history(target_id=uuid4())
                assert empty.total == 0 and empty.items == []
                bounded = await service.list_reconciliation_history(
                    server_id=servers[0].id,
                    limit=0,
                    offset=-1,
                )
                assert [entry.id for entry in bounded.items] == [expected[0].id]
                assert (
                    await service.list_reconciliation_history(
                        server_id=servers[0].id,
                        offset=6,
                    )
                ).items == []
                await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
