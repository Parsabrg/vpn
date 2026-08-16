"""Shared Redis convention for staging one-time email payload secrets.

`EmailDelivery` deliberately never stores a message body or one-time link
(see its docstring in `models.operations`), so the raw secret that only
exists in memory at issuance time is staged here, keyed by the delivery
row's id, for the worker service to read once and deliver. Redis already
holds equivalently sensitive capability tokens (admin sessions, CSRF
secrets) behind the same backend-only, no-public-port trust boundary, so
this reuses that boundary rather than encrypting the payload separately.

The worker is a standalone service that does not import `nebula_api`, so it
re-implements this exact key convention independently; keep the two in sync.
"""

import json
from typing import Protocol
from uuid import UUID

KEY_PREFIX = "nebula:email-outbox:v1"


class EmailOutboxRedisClient(Protocol):
    async def set(self, name: str, value: str, *, ex: int, nx: bool) -> object: ...


class EmailOutboxUnavailable(RuntimeError):
    """Raised when a staged payload could not be durably written."""


def email_outbox_key(delivery_id: UUID) -> str:
    """Return the shared key convention also implemented by the worker service."""

    return f"{KEY_PREFIX}:{delivery_id}"


async def stage_email_payload(
    client: EmailOutboxRedisClient,
    *,
    delivery_id: UUID,
    payload: dict[str, str],
    ttl_seconds: int,
) -> None:
    """Idempotently stage a payload once; a repeat call for the same id is a no-op."""

    if not 1 <= ttl_seconds <= 30 * 24 * 3_600:
        raise ValueError("email outbox payload TTL is invalid")
    try:
        # A `None` result means the key already existed (an idempotent retry
        # staging the same delivery id again); that is a success, not a failure.
        await client.set(
            email_outbox_key(delivery_id),
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            ex=ttl_seconds,
            nx=True,
        )
    except Exception as error:
        raise EmailOutboxUnavailable("email outbox payload could not be staged") from error
