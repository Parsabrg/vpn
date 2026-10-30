"""Real-PostgreSQL proof that pruning deletes old history and nothing else.

The interesting parts of this are all database behaviour, which a scripted
session cannot show: `reconciliation_records` references `agent_operations`
with ON DELETE RESTRICT, so the order of the passes matters and an operation
still referenced by a newer record must survive; and the audit table is
append-only to the application role, which is what the refusal path exists
for.
"""

import asyncio
import os
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.retention import RetentionPolicy, prune_history

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
LONG_AGO = NOW - timedelta(days=400)
A_WHILE_AGO = NOW - timedelta(days=120)
RECENTLY = NOW - timedelta(days=3)


def _requires_postgres() -> str:
    return os.environ.get("NEBULA_DATABASE_URL", "")


@pytest.mark.skipif(not _requires_postgres(), reason="PostgreSQL is not configured")
def test_pruning_deletes_history_past_the_policy_and_keeps_the_rest() -> None:
    engine = create_database_engine(_requires_postgres())
    session_factory = create_session_factory(engine)
    unique = uuid4().hex[:12]
    server_id = uuid4()
    old_operation = uuid4()
    referenced_operation = uuid4()
    recent_operation = uuid4()
    old_record = uuid4()
    recent_record = uuid4()
    old_health = uuid4()
    recent_health = uuid4()
    old_sent_email = uuid4()
    old_pending_email = uuid4()

    async def execute(sql: str, **params: object) -> None:
        async with engine.begin() as connection:
            await connection.execute(text(sql), params)

    async def exists(table: str, identifier: UUID) -> bool:
        async with engine.begin() as connection:
            found = await connection.scalar(
                text(f"select 1 from {table} where id = :id"),  # noqa: S608
                {"id": identifier},
            )
            return found is not None

    async def scenario() -> None:
        await execute(
            """
            insert into vpn_servers (id, code, display_name, public_host, agent_host,
                                     agent_port, state)
            values (:id, :code, :code, 'host.example.test', '127.0.0.1', 9443, 'active')
            """,
            id=server_id,
            code=f"prune-{unique}",
        )
        for identifier, requested_at in (
            (old_operation, LONG_AGO),
            (referenced_operation, LONG_AGO),
            (recent_operation, RECENTLY),
        ):
            await execute(
                """
                insert into agent_operations (id, vpn_server_id, idempotency_key, correlation_id,
                                              operation_kind, target_kind, target_id, state,
                                              desired_generation, attempt_count,
                                              request_fingerprint, requested_at, finished_at)
                values (:id, :server, :key, :correlation, 'provision_device', 'wireguard_peer',
                        :target, 'succeeded', 1, 1, :fingerprint, :requested_at, :requested_at)
                """,
                id=identifier,
                server=server_id,
                key=uuid4(),
                correlation=uuid4(),
                target=uuid4(),
                # The table requires 64 hex characters; the value itself is
                # never read back here.
                fingerprint=f"{identifier.hex}{identifier.hex}",
                requested_at=requested_at,
            )
        # One record older than the cutoff, and one newer that still points at
        # an operation older than it -- the case a single cutoff would break on.
        for identifier, operation, checked_at in (
            (old_record, old_operation, A_WHILE_AGO),
            (recent_record, referenced_operation, RECENTLY),
        ):
            await execute(
                """
                insert into reconciliation_records (id, vpn_server_id, agent_operation_id,
                                                    target_kind, target_id, desired_generation,
                                                    observed_generation, outcome, checked_at)
                values (:id, :server, :operation, 'wireguard_peer', :target, 1, 1,
                        'in_sync', :checked_at)
                """,
                id=identifier,
                server=server_id,
                operation=operation,
                target=uuid4(),
                checked_at=checked_at,
            )
        for identifier, observed_at in ((old_health, A_WHILE_AGO), (recent_health, RECENTLY)):
            await execute(
                """
                insert into server_health (id, vpn_server_id, state, source, observed_at)
                values (:id, :server, 'healthy', 'agent', :observed_at)
                """,
                id=identifier,
                server=server_id,
                observed_at=observed_at,
            )
        for identifier, state in ((old_sent_email, "sent"), (old_pending_email, "pending")):
            await execute(
                """
                insert into email_deliveries (id, deduplication_key, template_code,
                                              recipient_address, subject_kind, subject_id,
                                              state, attempt_count, available_at, sent_at)
                values (:id, :dedupe, 'password_reset', :address, 'user', :subject,
                        :state, 1, :available_at, :sent_at)
                """,
                id=identifier,
                dedupe=uuid4(),
                address=f"prune-{identifier.hex[:8]}@example.com",
                subject=uuid4(),
                state=state,
                available_at=A_WHILE_AGO,
                # The table requires one exactly when the state is 'sent'.
                sent_at=A_WHILE_AGO if state == "sent" else None,
            )

        summary = await prune_history(
            session_factory,
            RetentionPolicy(audit_days=365, operational_days=90),
            now=NOW,
        )

        assert await exists("reconciliation_records", old_record) is False
        assert await exists("reconciliation_records", recent_record) is True
        assert await exists("server_health", old_health) is False
        assert await exists("server_health", recent_health) is True
        # Terminal and old goes; old but still in flight stays, because a
        # pending row is work the worker has not done yet.
        assert await exists("email_deliveries", old_sent_email) is False
        assert await exists("email_deliveries", old_pending_email) is True
        assert await exists("agent_operations", old_operation) is False
        assert await exists("agent_operations", recent_operation) is True
        # Old, but a reconciliation record newer than the cutoff still points
        # at it -- deleting it would violate the ON DELETE RESTRICT foreign key.
        assert await exists("agent_operations", referenced_operation) is True
        assert summary.total_deleted >= 4

    async def cleanup() -> None:
        await execute("delete from reconciliation_records where vpn_server_id = :id", id=server_id)
        await execute("delete from server_health where vpn_server_id = :id", id=server_id)
        await execute("delete from agent_operations where vpn_server_id = :id", id=server_id)
        await execute(
            "delete from email_deliveries where id = any(:ids)",
            ids=[old_sent_email, old_pending_email],
        )
        await execute("delete from vpn_servers where id = :id", id=server_id)

    async def main() -> None:
        try:
            await scenario()
        finally:
            await cleanup()
            await engine.dispose()

    asyncio.run(main())


@pytest.mark.skipif(not _requires_postgres(), reason="PostgreSQL is not configured")
def test_an_append_only_audit_table_is_reported_rather_than_silently_skipped() -> None:
    """The application role holds INSERT and SELECT on `audit_logs` and
    nothing else, which is what makes an audit row evidence. Pruning under
    that credential has to say so, not appear to have worked."""

    engine = create_database_engine(_requires_postgres())
    session_factory = create_session_factory(engine)
    marker = uuid4()

    async def main() -> None:
        try:
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        """
                        insert into audit_logs (id, actor_kind, target_kind, target_id,
                                                event_code, outcome, request_id, recorded_at)
                        values (:id, 'system', 'auth_attempt', :target, 'user_authenticated',
                                'succeeded', :request, :recorded_at)
                        """
                    ),
                    {
                        "id": marker,
                        "target": uuid4(),
                        "request": uuid4(),
                        "recorded_at": LONG_AGO,
                    },
                )
                grants = await connection.scalar(
                    text(
                        """
                        select count(*) from information_schema.role_table_grants
                        where table_name = 'audit_logs' and privilege_type = 'DELETE'
                          and grantee = current_user
                        """
                    )
                )

            summary = await prune_history(session_factory, RetentionPolicy(audit_days=365), now=NOW)

            if grants:
                # The migration credential, which is allowed to prune.
                assert summary.deleted.get("audit_logs", 0) >= 1
            else:
                assert "audit_logs" in summary.refused
                assert summary.refused["audit_logs"]
                async with engine.begin() as connection:
                    still_there = await connection.scalar(
                        text("select 1 from audit_logs where id = :id"), {"id": marker}
                    )
                assert still_there is not None
        finally:
            # Best effort: under the application credential this delete is
            # exactly the thing the table refuses, which is the point of the
            # test rather than a failure of it.
            with suppress(ProgrammingError):
                async with engine.begin() as connection:
                    await connection.execute(
                        text("delete from audit_logs where id = :id"), {"id": marker}
                    )
            await engine.dispose()

    asyncio.run(main())
