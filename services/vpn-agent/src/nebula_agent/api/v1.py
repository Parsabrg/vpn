"""Typed WireGuard operation routes: one route per OPERATION_KINDS value,
each validated against its own request/response model (see drivers/base.py).

Mutating operations (provision/revoke/enable/disable) are idempotency-ledgered
so a retried request with the same idempotency_key replays the stored
response instead of re-running the driver. health/reconcile are read-only and
bypass the ledger entirely.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from nebula_agent.drivers.base import (
    DisableDeviceRequest,
    DisableDeviceResponse,
    EnableDeviceRequest,
    EnableDeviceResponse,
    HealthRequest,
    HealthResponse,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ReconcileRequest,
    ReconcileResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
    WireGuardDriver,
)
from nebula_agent.ledger import OperationLedger

router = APIRouter(prefix="/v1/operations", tags=["operations"])

_MAX_OPERATION_BODY_BYTES = 16 * 1024


async def enforce_body_size_limit(request: Request) -> None:
    """Defense in depth beyond the typed models themselves, which already
    have no unbounded free-form fields."""

    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > _MAX_OPERATION_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="request body too large"
        )


def get_driver(request: Request) -> WireGuardDriver:
    driver: WireGuardDriver = request.app.state.driver
    return driver


def get_ledger(request: Request) -> OperationLedger:
    ledger: OperationLedger = request.app.state.ledger
    return ledger


async def _dispatch_ledgered[ResponseT: BaseModel](
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


@router.post(
    "/provision-device",
    response_model=ProvisionDeviceResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def provision_device(
    payload: ProvisionDeviceRequest,
    driver: Annotated[WireGuardDriver, Depends(get_driver)],
    ledger: Annotated[OperationLedger, Depends(get_ledger)],
) -> ProvisionDeviceResponse:
    return await _dispatch_ledgered(
        ledger=ledger,
        idempotency_key=payload.idempotency_key,
        operation_kind="provision_device",
        target_id=payload.target_id,
        response_model=ProvisionDeviceResponse,
        run=lambda: driver.provision_device(payload),
    )


@router.post(
    "/revoke-device",
    response_model=RevokeDeviceResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def revoke_device(
    payload: RevokeDeviceRequest,
    driver: Annotated[WireGuardDriver, Depends(get_driver)],
    ledger: Annotated[OperationLedger, Depends(get_ledger)],
) -> RevokeDeviceResponse:
    return await _dispatch_ledgered(
        ledger=ledger,
        idempotency_key=payload.idempotency_key,
        operation_kind="revoke_device",
        target_id=payload.target_id,
        response_model=RevokeDeviceResponse,
        run=lambda: driver.revoke_device(payload),
    )


@router.post(
    "/enable-device",
    response_model=EnableDeviceResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def enable_device(
    payload: EnableDeviceRequest,
    driver: Annotated[WireGuardDriver, Depends(get_driver)],
    ledger: Annotated[OperationLedger, Depends(get_ledger)],
) -> EnableDeviceResponse:
    return await _dispatch_ledgered(
        ledger=ledger,
        idempotency_key=payload.idempotency_key,
        operation_kind="enable_device",
        target_id=payload.target_id,
        response_model=EnableDeviceResponse,
        run=lambda: driver.enable_device(payload),
    )


@router.post(
    "/disable-device",
    response_model=DisableDeviceResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def disable_device(
    payload: DisableDeviceRequest,
    driver: Annotated[WireGuardDriver, Depends(get_driver)],
    ledger: Annotated[OperationLedger, Depends(get_ledger)],
) -> DisableDeviceResponse:
    return await _dispatch_ledgered(
        ledger=ledger,
        idempotency_key=payload.idempotency_key,
        operation_kind="disable_device",
        target_id=payload.target_id,
        response_model=DisableDeviceResponse,
        run=lambda: driver.disable_device(payload),
    )


@router.post(
    "/health",
    response_model=HealthResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def health(
    payload: HealthRequest,
    driver: Annotated[WireGuardDriver, Depends(get_driver)],
) -> HealthResponse:
    return await driver.health(payload)


@router.post(
    "/reconcile",
    response_model=ReconcileResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def reconcile(
    payload: ReconcileRequest,
    driver: Annotated[WireGuardDriver, Depends(get_driver)],
) -> ReconcileResponse:
    return await driver.reconcile(payload)
