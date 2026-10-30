"""Shared idempotency-ledgered dispatch, used by both api/v1.py (WireGuard)
and api/v1_xray.py (Xray) so a retried request with the same idempotency_key
replays the stored response instead of re-running the driver, regardless of
which protocol's router it hit.
"""

from collections.abc import Awaitable, Callable
from uuid import UUID

from fastapi import HTTPException, Request, status
from pydantic import BaseModel

from nebula_agent.ledger import OperationLedger

_MAX_OPERATION_BODY_BYTES = 16 * 1024


async def enforce_body_size_limit(request: Request) -> None:
    """Defense in depth beyond the typed models themselves, which already
    have no unbounded free-form fields."""

    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > _MAX_OPERATION_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="request body too large"
        )


def get_ledger(request: Request) -> OperationLedger:
    ledger: OperationLedger = request.app.state.ledger
    return ledger


async def dispatch_ledgered[ResponseT: BaseModel](
    *,
    ledger: OperationLedger,
    idempotency_key: UUID,
    operation_kind: str,
    target_id: UUID,
    response_model: type[ResponseT],
    run: Callable[[], Awaitable[ResponseT]],
) -> ResponseT:
    cached = ledger.lookup(idempotency_key)
    if cached is not None:
        if cached.operation_kind != operation_kind or cached.target_id != str(target_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="idempotency_key was already used for a different operation",
            )
        return response_model.model_validate_json(cached.response_json)
    response = await run()
    ledger.record(
        idempotency_key=idempotency_key,
        operation_kind=operation_kind,
        target_id=target_id,
        applied_generation=response.applied_generation,  # type: ignore[attr-defined]
        response_json=response.model_dump_json(),
    )
    return response
