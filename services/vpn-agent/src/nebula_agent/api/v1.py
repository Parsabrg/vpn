"""Typed WireGuard operation routes: one route per OPERATION_KINDS value,
each validated against its own request/response model (see drivers/base.py).

Mutating operations (provision/revoke/enable/disable) are idempotency-ledgered
so a retried request with the same idempotency_key replays the stored
response instead of re-running the driver. health/reconcile are read-only and
bypass the ledger entirely.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from nebula_agent.api._dispatch import dispatch_ledgered, enforce_body_size_limit, get_ledger
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


def get_driver(request: Request) -> WireGuardDriver:
    driver: WireGuardDriver = request.app.state.driver
    return driver


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
    return await dispatch_ledgered(
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
    return await dispatch_ledgered(
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
    return await dispatch_ledgered(
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
    return await dispatch_ledgered(
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
