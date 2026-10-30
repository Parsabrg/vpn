import asyncio
from uuid import uuid4

from nebula_worker.outbox import email_outbox_key, read_email_payload


class FakeRedis:
    def __init__(self, value: bytes | str | None = None, *, raises: bool = False) -> None:
        self.value = value
        self.raises = raises

    async def get(self, _name: str) -> bytes | str | None:
        if self.raises:
            raise ConnectionError("redis unavailable")
        return self.value


def test_key_format_is_stable() -> None:
    delivery_id = uuid4()

    assert email_outbox_key(delivery_id) == f"nebula:email-outbox:v1:{delivery_id}"


def test_reads_a_staged_bytes_payload() -> None:
    payload = asyncio.run(read_email_payload(FakeRedis(b'{"token": "v1.canary"}'), uuid4()))

    assert payload == {"token": "v1.canary"}


def test_reads_a_staged_string_payload() -> None:
    payload = asyncio.run(read_email_payload(FakeRedis('{"token": "v1.canary"}'), uuid4()))

    assert payload == {"token": "v1.canary"}


def test_missing_payload_returns_none() -> None:
    payload = asyncio.run(read_email_payload(FakeRedis(None), uuid4()))

    assert payload is None


def test_malformed_json_returns_none() -> None:
    payload = asyncio.run(read_email_payload(FakeRedis("not-json"), uuid4()))

    assert payload is None


def test_non_object_json_returns_none() -> None:
    payload = asyncio.run(read_email_payload(FakeRedis("[1, 2]"), uuid4()))

    assert payload is None


def test_non_string_values_return_none() -> None:
    payload = asyncio.run(read_email_payload(FakeRedis('{"count": 1}'), uuid4()))

    assert payload is None


def test_redis_failure_returns_none() -> None:
    payload = asyncio.run(read_email_payload(FakeRedis(raises=True), uuid4()))

    assert payload is None
