import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_worker.adapters.base import EmailSendError
from nebula_worker.poller import (
    ClaimedDelivery,
    claim_batch,
    deliver_one,
    poll_once,
    reclaim_expired_leases,
)
from nebula_worker.settings import Settings

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> "FakeResult":
        return self

    def all(self) -> list[dict[str, Any]]:
        return self._rows


class FakeConnection:
    def __init__(
        self,
        claim_rows: list[dict[str, Any]],
        reclaim_rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self._claim_rows = claim_rows
        self._reclaim_rows = reclaim_rows or []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(
        self, statement: object, params: Mapping[str, Any] | None = None
    ) -> FakeResult:
        sql = str(statement)
        self.calls.append((sql, dict(params or {})))
        if "RETURNING id, template_code" in sql:
            rows, self._claim_rows = self._claim_rows, []
            return FakeResult(rows)
        if "RETURNING id, state" in sql:
            rows, self._reclaim_rows = self._reclaim_rows, []
            return FakeResult(rows)
        return FakeResult([])


class _BeginContext:
    def __init__(self, connection: FakeConnection) -> None:
        self._connection = connection

    async def __aenter__(self) -> FakeConnection:
        return self._connection

    async def __aexit__(self, *_args: object) -> bool:
        return False


class FakeEngine:
    def __init__(
        self,
        claim_rows: list[dict[str, Any]] | None = None,
        reclaim_rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self.connection = FakeConnection(claim_rows or [], reclaim_rows)

    def begin(self) -> _BeginContext:
        return _BeginContext(self.connection)


class FakeRedis:
    def __init__(self, payload: str | None) -> None:
        self.payload = payload

    async def get(self, _name: str) -> str | None:
        return self.payload


class FakeAdapter:
    def __init__(self, *, message_id: str = "provider-id", error: Exception | None = None) -> None:
        self.message_id = message_id
        self.error = error
        self.calls: list[tuple[str, str, str]] = []

    async def send(self, *, to: str, subject: str, body: str) -> str:
        self.calls.append((to, subject, body))
        if self.error is not None:
            raise self.error
        return self.message_id


def delivery(*, attempt_count: int = 0, template_code: str = "user_activation") -> ClaimedDelivery:
    return ClaimedDelivery(
        id=uuid4(),
        template_code=template_code,
        recipient_address="user@example.com",
        attempt_count=attempt_count,
    )


def _sql_kinds(calls: list[tuple[str, dict[str, Any]]]) -> list[str]:
    kinds = []
    for sql, _params in calls:
        if "RETURNING id, template_code" in sql:
            kinds.append("claim")
        elif "SET state = 'sent'" in sql:
            kinds.append("sent")
        elif "SET state = 'pending'" in sql:
            kinds.append("reschedule")
        elif "SET state = 'failed'" in sql:
            kinds.append("failed")
        elif "INSERT INTO audit_logs" in sql:
            kinds.append("audit")
        else:
            kinds.append("unknown")
    return kinds


def test_claim_batch_parses_returned_rows() -> None:
    request_id: UUID = uuid4()
    engine = FakeEngine(
        claim_rows=[
            {
                "id": request_id,
                "template_code": "user_activation",
                "recipient_address": "user@example.com",
                "attempt_count": 0,
            }
        ]
    )

    claimed = asyncio.run(
        claim_batch(cast(AsyncEngine, engine), batch_size=10, lease_seconds=60, now=NOW)
    )

    assert claimed == [ClaimedDelivery(request_id, "user_activation", "user@example.com", 0)]
    _sql, params = engine.connection.calls[0]
    assert params["batch_size"] == 10


def test_deliver_one_sends_and_marks_sent() -> None:
    engine = FakeEngine()
    adapter = FakeAdapter(message_id="canary-id")
    item = delivery()

    asyncio.run(
        deliver_one(
            cast(AsyncEngine, engine),
            FakeRedis('{"token": "v1.canary", "expires_at": "2026-08-01T00:00:00Z"}'),
            adapter,
            item,
            settings=Settings(),
            now=NOW,
        )
    )

    assert len(adapter.calls) == 1
    to, subject, body = adapter.calls[0]
    assert to == "user@example.com"
    assert subject == "Activate your Nebula account"
    assert "v1.canary" in body
    assert _sql_kinds(engine.connection.calls) == ["sent", "audit"]
    _sql, params = engine.connection.calls[0]
    assert params["provider_message_id"] == "canary-id"


def test_deliver_one_marks_failed_when_payload_is_missing() -> None:
    engine = FakeEngine()
    item = delivery()

    asyncio.run(
        deliver_one(
            cast(AsyncEngine, engine),
            FakeRedis(None),
            FakeAdapter(),
            item,
            settings=Settings(),
            now=NOW,
        )
    )

    assert _sql_kinds(engine.connection.calls) == ["failed", "audit"]
    _sql, params = engine.connection.calls[1]
    assert params["reason_code"] == "payload_unavailable"


def test_deliver_one_marks_failed_for_an_unknown_template() -> None:
    engine = FakeEngine()
    item = delivery(template_code="not_a_real_template")

    asyncio.run(
        deliver_one(
            cast(AsyncEngine, engine),
            FakeRedis("{}"),
            FakeAdapter(),
            item,
            settings=Settings(),
            now=NOW,
        )
    )

    assert _sql_kinds(engine.connection.calls) == ["failed", "audit"]


def test_deliver_one_reschedules_a_transient_send_failure() -> None:
    engine = FakeEngine()
    item = delivery(attempt_count=0)
    adapter = FakeAdapter(error=EmailSendError("smtp down"))

    asyncio.run(
        deliver_one(
            cast(AsyncEngine, engine),
            FakeRedis("{}"),
            adapter,
            item,
            settings=Settings(max_attempts=8),
            now=NOW,
        )
    )

    assert _sql_kinds(engine.connection.calls) == ["reschedule", "audit"]


def test_deliver_one_marks_failed_once_attempts_are_exhausted() -> None:
    engine = FakeEngine()
    item = delivery(attempt_count=7)
    adapter = FakeAdapter(error=EmailSendError("smtp down"))

    asyncio.run(
        deliver_one(
            cast(AsyncEngine, engine),
            FakeRedis("{}"),
            adapter,
            item,
            settings=Settings(max_attempts=8),
            now=NOW,
        )
    )

    assert _sql_kinds(engine.connection.calls) == ["failed", "audit"]


def test_poll_once_processes_the_whole_claimed_batch() -> None:
    rows = [
        {
            "id": uuid4(),
            "template_code": "request_rejected",
            "recipient_address": "user@example.com",
            "attempt_count": 0,
        }
        for _ in range(2)
    ]
    engine = FakeEngine(claim_rows=list(rows))
    adapter = FakeAdapter()

    processed = asyncio.run(
        poll_once(
            cast(AsyncEngine, engine),
            FakeRedis("{}"),
            adapter,
            Settings(),
            clock=lambda: NOW,
        )
    )

    assert processed == 2
    assert len(adapter.calls) == 2


def test_poll_once_returns_zero_for_an_empty_batch() -> None:
    engine = FakeEngine()

    processed = asyncio.run(
        poll_once(cast(AsyncEngine, engine), FakeRedis(None), FakeAdapter(), Settings())
    )

    assert processed == 0


def test_reclaim_returns_an_expired_lease_to_the_queue() -> None:
    engine = FakeEngine(reclaim_rows=[{"id": uuid4(), "state": "pending"}])

    reclaimed = asyncio.run(
        reclaim_expired_leases(cast(AsyncEngine, engine), max_attempts=8, now=NOW)
    )

    assert reclaimed == 1
    sql, params = engine.connection.calls[0]
    assert "state = 'sending'" in sql
    assert "leased_until < :now" in sql
    assert params["max_attempts"] == 8
    # The reclaim must also leave an audit trail, not silently resurrect rows.
    assert any("INSERT INTO audit_logs" in call_sql for call_sql, _ in engine.connection.calls)


def test_reclaim_audits_an_exhausted_delivery_as_failed() -> None:
    engine = FakeEngine(reclaim_rows=[{"id": uuid4(), "state": "failed"}])

    asyncio.run(reclaim_expired_leases(cast(AsyncEngine, engine), max_attempts=1, now=NOW))

    audits = [
        params
        for call_sql, params in engine.connection.calls
        if "INSERT INTO audit_logs" in call_sql
    ]
    assert [entry["outcome"] for entry in audits] == ["failed"]
    assert [entry["reason_code"] for entry in audits] == ["lease_expired"]


def test_reclaim_does_nothing_when_no_lease_has_expired() -> None:
    engine = FakeEngine()

    reclaimed = asyncio.run(
        reclaim_expired_leases(cast(AsyncEngine, engine), max_attempts=8, now=NOW)
    )

    assert reclaimed == 0
    assert not any("INSERT INTO audit_logs" in call_sql for call_sql, _ in engine.connection.calls)


def test_poll_once_reclaims_expired_leases_before_claiming() -> None:
    engine = FakeEngine(reclaim_rows=[{"id": uuid4(), "state": "pending"}])

    asyncio.run(poll_once(cast(AsyncEngine, engine), FakeRedis(None), FakeAdapter(), Settings()))

    kinds = [
        "reclaim"
        if "RETURNING id, state" in sql
        else "claim"
        if "RETURNING id, template" in sql
        else "other"
        for sql, _ in engine.connection.calls
    ]
    assert kinds.index("reclaim") < kinds.index("claim")


def test_poll_once_continues_after_one_delivery_raises() -> None:
    """A single unexpected failure must not strand the rest of the batch --
    those rows would keep their lease and go unsent until reclaimed."""

    rows = [
        {
            "id": uuid4(),
            "template_code": "request_rejected",
            "recipient_address": "user@example.com",
            "attempt_count": 0,
        }
        for _ in range(3)
    ]
    engine = FakeEngine(claim_rows=list(rows))

    class ExplodingOnFirstAdapter(FakeAdapter):
        async def send(self, *, to: str, subject: str, body: str) -> str:
            self.calls.append((to, subject, body))
            if len(self.calls) == 1:
                raise RuntimeError("unexpected boom")
            return self.message_id

    adapter = ExplodingOnFirstAdapter()

    processed = asyncio.run(
        poll_once(
            cast(AsyncEngine, engine),
            FakeRedis("{}"),
            adapter,
            Settings(),
            clock=lambda: NOW,
        )
    )

    assert processed == 3
    assert len(adapter.calls) == 3
