"""User-facing WireGuard peer provisioning HTTP routes."""

import logging
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
from nebula_api.cdn import CDN_PORT, CdnRoute, cdn_route_for
from nebula_api.devices.schemas import (
    RequestPeerRequest,
    RequestXrayClientRequest,
    RevokePeerRequest,
    WireGuardPeerResponse,
    XrayClientResponse,
)
from nebula_api.devices.schemas import (
    RevokeXrayClientRequest as RevokeXrayClientHttpRequest,
)
from nebula_api.dns_profiles import resolvers_for
from nebula_api.provisioning.service import (
    OperationInProgress,
    ProvisioningAmbiguous,
    ProvisioningError,
    ProvisioningRateLimited,
    ProvisioningRejected,
    ProvisioningService,
    RequestPeerResult,
    RequestXrayClientResult,
    ServerUnderMaintenance,
    TrafficQuotaExhausted,
    XrayOperationInProgress,
)

router = APIRouter(prefix="/v1/devices", tags=["devices"])
_LOGGER = logging.getLogger(__name__)

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
    if isinstance(error, (OperationInProgress, XrayOperationInProgress)):
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
    if isinstance(error, TrafficQuotaExhausted):
        # 402 rather than a 400 among the others: the client has to tell this
        # apart from every other refusal in order to say why, and matching on
        # a detail string would break the first time the wording changed.
        # Nothing else in this API uses this status.
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=str(error)
        ) from None
    if isinstance(error, ServerUnderMaintenance):
        # 423, used for nothing else, so the app can say this without
        # matching wording. An app from before it shows this sentence.
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=str(error)) from None
    if isinstance(error, ProvisioningRejected):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_GENERIC_DETAIL
        ) from None
    # A bare ProvisioningError is an internal invariant failure (rows vanishing
    # mid-finalization), not a bad request -- reporting it as 4xx would both
    # mislead the client and bury a real server fault in client-error noise.
    # The message may name internal state, so it is logged, never returned.
    _LOGGER.error("provisioning failed with an internal error", exc_info=error)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=_GENERIC_DETAIL
    ) from None


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


def _to_xray_response(
    result: RequestXrayClientResult, route: CdnRoute | None, client_dns: list[str] | None = None
) -> XrayClientResponse:
    # A client that reached the API through the CDN hostname gets tunnel
    # endpoints through it as well; see nebula_api/cdn.py.
    # A profile with its own encryption and no TLS (Shadowsocks-2022, VLESS
    # Encryption, VMess) is dialled at the server itself: the CDN carries TLS.
    direct = result.protocol != "vless" or result.encryption is not None
    through = route.tunnel(result.transport) if route and not direct else None
    host, ech = through if through else (None, None)
    return XrayClientResponse(
        client_id=result.client_id,
        uuid=result.uuid,
        server_address=host or result.server_address,
        port=CDN_PORT if host else result.port,
        sni=host or result.sni,
        transport=result.transport,
        transport_security="tls" if host else result.transport_security,
        path=result.path,
        service_name=result.service_name,
        obfs_password=result.obfs_password,
        protocol=result.protocol,
        method=result.method,
        password=result.password,
        encryption=result.encryption,
        ad_block=result.ad_block,
        ech_config_list=ech,
        # Xray only: Hysteria2 runs outside Xray, where the agent's redirect
        # does not reach.
        client_dns=list(client_dns or []) if result.transport != "hysteria" else [],
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
            protocol_profile_code=payload.protocol_profile_code,
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


@router.post("/{device_id}/xray-client", response_model=XrayClientResponse)
async def request_xray_client(
    device_id: UUID,
    payload: RequestXrayClientRequest,
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> XrayClientResponse:
    require_json_request(request)
    try:
        result = await _service(request).request_xray_client(
            user_id=principal.user_id,
            device_id=device_id,
            server_code=payload.server_code,
            protocol_profile_code=payload.protocol_profile_code,
            request_id=uuid4(),
            network_prefix=client_network_prefix(request),
        )
    except (ProvisioningError, AuthStateUnavailable) as error:
        _raise_provisioning_error(error)
    apply_auth_response_headers(response)
    profile = await _service(request).dns_profile_for(
        user_id=principal.user_id, device_id=device_id
    )
    settings = request.app.state.settings
    return _to_xray_response(
        result,
        cdn_route_for(request) if settings.behind_cdn(payload.server_code) else None,
        resolvers_for(profile, settings.xray_client_dns),
    )


@router.post("/{device_id}/xray-client/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_xray_client(
    device_id: UUID,
    payload: RevokeXrayClientHttpRequest,
    request: Request,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> Response:
    require_json_request(request)
    try:
        await _service(request).revoke_xray_client(
            user_id=principal.user_id,
            device_id=device_id,
            server_code=payload.server_code,
            protocol_profile_code=payload.protocol_profile_code,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (ProvisioningError, AuthStateUnavailable) as error:
        _raise_provisioning_error(error)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    apply_auth_response_headers(response)
    return response
