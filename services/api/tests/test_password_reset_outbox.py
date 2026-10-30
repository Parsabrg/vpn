"""Production's password-reset sender stages the code for the worker."""

import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

from nebula_api.accounts.email_outbox import email_outbox_key, outbox_password_reset_delivery


class _Redis:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int, bool]] = []

    async def set(self, name: str, value: str, *, ex: int, nx: bool) -> object:
        self.calls.append((name, value, ex, nx))
        return True


def test_stages_the_code_where_the_worker_reads_it() -> None:
    redis = _Redis()
    deliver = outbox_password_reset_delivery(
        redis, ttl_minutes=30, clock=lambda: datetime(2026, 10, 23, 15, 0, tzinfo=UTC)
    )
    delivery_id = uuid4()

    asyncio.run(deliver(recipient="a@example.test", token="code-123", delivery_id=delivery_id))  # noqa: S106 - a test value

    [(key, value, ttl, nx)] = redis.calls
    assert key == email_outbox_key(delivery_id)
    # The worker's password_reset template reads exactly these two fields.
    assert json.loads(value) == {"token": "code-123", "expires_at": "2026-10-23 15:30 UTC"}
    assert (ttl, nx) == (1800, True)
    # The address stays in the delivery row, not in Redis.
    assert "a@example.test" not in value
