"""Typed Xray operation routes, mirroring api/v1.py's shape for the VLESS
path: provision/revoke are idempotency-ledgered through the same
OperationLedger (its conflict check is keyed on operation_kind/target_id,
already safe to share across protocols); health is read-only and bypasses
the ledger entirely.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from nebula_agent.api._dispatch import dispatch_ledgered, enforce_body_size_limit, get_ledger
from nebula_agent.drivers.xray_base import (
    ProvisionXrayClientRequest,
    ProvisionXrayClientResponse,
    PruneXrayClientsRequest,
    PruneXrayClientsResponse,
    ReconcileXrayClientRequest,
    ReconcileXrayClientResponse,
    RevokeXrayClientRequest,
    RevokeXrayClientResponse,
    XrayDriver,
    XrayHealthRequest,
    XrayHealthResponse,
)
from nebula_agent.ledger import OperationLedger

router = APIRouter(prefix="/v1/xray-operations", tags=["xray-operations"])


def get_xray_driver(request: Request) -> XrayDriver:
    driver: XrayDriver = request.app.state.xray_driver
    return driver


@router.post(
    "/provision-client",
    response_model=ProvisionXrayClientResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def provision_client(
    payload: ProvisionXrayClientRequest,
    driver: Annotated[XrayDriver, Depends(get_xray_driver)],
    ledger: Annotated[OperationLedger, Depends(get_ledger)],
) -> ProvisionXrayClientResponse:
    return await dispatch_ledgered(
        ledger=ledger,
        idempotency_key=payload.idempotency_key,
        operation_kind="provision_device",
        target_id=payload.target_id,
        response_model=ProvisionXrayClientResponse,
        run=lambda: driver.provision_client(payload),
    )


@router.post(
    "/revoke-client",
    response_model=RevokeXrayClientResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def revoke_client(
    payload: RevokeXrayClientRequest,
    driver: Annotated[XrayDriver, Depends(get_xray_driver)],
    ledger: Annotated[OperationLedger, Depends(get_ledger)],
) -> RevokeXrayClientResponse:
    return await dispatch_ledgered(
        ledger=ledger,
        idempotency_key=payload.idempotency_key,
        operation_kind="revoke_device",
        target_id=payload.target_id,
        response_model=RevokeXrayClientResponse,
        run=lambda: driver.revoke_client(payload),
    )


@router.post(
    "/reconcile-client",
    response_model=ReconcileXrayClientResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def reconcile_client(
    payload: ReconcileXrayClientRequest,
    driver: Annotated[XrayDriver, Depends(get_xray_driver)],
) -> ReconcileXrayClientResponse:
    # Read-only, so no ledger -- same reasoning as api/v1.py's WireGuard
    # /reconcile and the health route below.
    return await driver.reconcile_client(payload)


@router.post(
    "/prune-clients",
    response_model=PruneXrayClientsResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def prune_clients(
    payload: PruneXrayClientsRequest,
    driver: Annotated[XrayDriver, Depends(get_xray_driver)],
) -> PruneXrayClientsResponse:
    # Not ledgered: the request carries no idempotency key because it is
    # inherently idempotent -- it states the desired end state rather than a
    # delta, so replaying it converges on the same set.
    return await driver.prune_clients(payload)


@router.post(
    "/health",
    response_model=XrayHealthResponse,
    dependencies=[Depends(enforce_body_size_limit)],
)
async def health(
    payload: XrayHealthRequest,
    driver: Annotated[XrayDriver, Depends(get_xray_driver)],
) -> XrayHealthResponse:
    return await driver.health(payload)
