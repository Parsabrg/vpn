"""User-facing WireGuard peer provisioning HTTP routes."""

from typing import Annotated, NoReturn, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from nebula_api.auth.http import (
    apply_auth_response_headers,
    client_network_prefix,
    require_json_request,
)
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.user_authorization import require_user_session
from nebula_api.auth.user_service import AuthenticatedUser
from nebula_api.devices.schemas import RequestPeerRequest, RevokePeerRequest, WireGuardPeerResponse
from nebula_api.provisioning.service import (
    DeviceAlreadyHasPeer,
    OperationInProgress,
    ProvisioningAmbiguous,
    ProvisioningError,
    ProvisioningRateLimited,
    ProvisioningService,
    RequestPeerResult,
)

router = APIRouter(prefix="/v1/devices", tags=["devices"])

_GENERIC_DETAIL = "Request was not accepted"


def _service(request: Request) -> ProvisioningService:
    service = getattr(request.app.state, "provisioning_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WireGuard provisioning is temporarily unavailable",
        )
    return cast(ProvisioningService, service)


def _raise_provisioning_error(error: Exception) -> NoReturn:
    if isinstance(error, ProvisioningRateLimited):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_GENERIC_DETAIL,
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from None
    if isinstance(error, (DeviceAlreadyHasPeer, OperationInProgress)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from None
    if isinstance(error, ProvisioningAmbiguous):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)
        ) from None
    if isinstance(error, AuthStateUnavailable):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WireGuard provisioning is temporarily unavailable",
        ) from None
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_GENERIC_DETAIL) from None


def _to_response(result: RequestPeerResult) -> WireGuardPeerResponse:
    return WireGuardPeerResponse(
        peer_id=result.peer_id,
        assigned_address=result.assigned_address,
        server_public_key=result.server_public_key,
        listen_port=result.listen_port,
        public_endpoint=result.public_endpoint,
        client_dns=result.client_dns,
        client_allowed_ips=result.client_allowed_ips,
        persistent_keepalive_seconds=result.persistent_keepalive_seconds,
    )


@router.post("/{device_id}/wireguard-peer", response_model=WireGuardPeerResponse)
async def request_wireguard_peer(
    device_id: UUID,
    payload: RequestPeerRequest,
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> WireGuardPeerResponse:
    require_json_request(request)
    try:
        result = await _service(request).request_peer(
            user_id=principal.user_id,
            device_id=device_id,
            server_code=payload.server_code,
            public_key=payload.public_key,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (ProvisioningError, AuthStateUnavailable) as error:
        _raise_provisioning_error(error)
    apply_auth_response_headers(response)
    return _to_response(result)


@router.post("/{device_id}/wireguard-peer/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_wireguard_peer(
    device_id: UUID,
    payload: RevokePeerRequest,
    request: Request,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> Response:
    require_json_request(request)
    try:
        await _service(request).revoke_peer(
            user_id=principal.user_id,
            device_id=device_id,
            server_code=payload.server_code,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (ProvisioningError, AuthStateUnavailable) as error:
        _raise_provisioning_error(error)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    apply_auth_response_headers(response)
    return response
