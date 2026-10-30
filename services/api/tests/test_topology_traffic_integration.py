"""Database sums preserve large recorded totals without loading identities."""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker

from nebula_api.db.engine import create_database_engine
from nebula_api.models.usage import CredentialUsage
from nebula_api.topology_admin.service import TopologyAdminService
from nebula_api.usage.service import usage_digest


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_traffic_summary_aggregates_all_sources_and_keeps_missing_timestamps_unknown() -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])

    async def scenario() -> None:
        try:
            async with engine.connect() as connection, connection.begin() as transaction:
                factory = async_sessionmaker(
                    connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
                )
                service = TopologyAdminService(factory)
                now = datetime.now(UTC)
                older = now - timedelta(days=1)
                async with factory() as session:
                    # Isolate these global aggregates inside a rolled-back transaction.
                    await session.execute(delete(CredentialUsage))
                    await session.commit()
                assert await service.get_traffic_summary() == []
                async with factory() as session:
                    for protocol, rx, tx, collected in (
                        ("wireguard", 3, 5, older),
                        ("wireguard", 7, 11, now),
                        ("xray", 2**63 - 1, 2**63 - 1, None),
                        ("xray", 9, 13, now),
                        ("hysteria2", 0, 0, None),
                        ("other-source", 17, 19, older),
                    ):
                        session.add(
                            CredentialUsage(
                                protocol=protocol,
                                identity=usage_digest(str(uuid4())),
                                rx_bytes=rx,
                                tx_bytes=tx,
                                last_rx_reading=0,
                                last_tx_reading=0,
                                last_collected_at=collected,
                                updated_at=now + timedelta(days=1),
                            )
                        )
                    await session.commit()

                entries = await service.get_traffic_summary()
                assert [entry.protocol for entry in entries] == [
                    "hysteria2",
                    "other-source",
                    "wireguard",
                    "xray",
                ]
                assert {
                    entry.protocol: (entry.rx_bytes, entry.tx_bytes, entry.newest_collected_at)
                    for entry in entries
                } == {
                    "hysteria2": (0, 0, None),
                    "other-source": (17, 19, older),
                    "wireguard": (10, 16, now),
                    "xray": (2**63 + 8, 2**63 + 12, now),
                }
                await transaction.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())
