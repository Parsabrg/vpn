"""Read the one-time email payload the API staged in Redis for a delivery.

Mirrors the key convention in `nebula_api.accounts.email_outbox` on the API
side (`nebula:email-outbox:v1:{delivery_id}`). The two are kept in sync by
convention, not shared code, since this service does not import `nebula_api`.
"""

import json
from typing import Protocol
from uuid import UUID

KEY_PREFIX = "nebula:email-outbox:v1"


class OutboxRedisClient(Protocol):
    async def get(self, name: str) -> bytes | str | None: ...


def email_outbox_key(delivery_id: UUID) -> str:
    return f"{KEY_PREFIX}:{delivery_id}"


async def read_email_payload(client: OutboxRedisClient, delivery_id: UUID) -> dict[str, str] | None:
    """Return the staged payload, or `None` if it is missing, expired, or malformed."""

    try:
        raw = await client.get(email_outbox_key(delivery_id))
    except Exception:
        return None
    if raw is None:
        return None
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in payload.items()
    ):
        return None
    return payload
