"""User-facing, session-gated server/profile discovery route."""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.auth.user_authorization import require_user_session
from nebula_api.auth.user_service import AuthenticatedUser
from nebula_api.cdn import CDN_PORT, cdn_route_for
from nebula_api.servers.schemas import (
    AvailableProfileItem,
    AvailableServerItem,
    AvailableServerListResponse,
)
from nebula_api.servers.service import ServerDiscoveryService

router = APIRouter(prefix="/v1/servers", tags=["servers"])


def _service(request: Request) -> ServerDiscoveryService:
    service = getattr(request.app.state, "server_discovery_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server discovery is temporarily unavailable",
        )
    return cast(ServerDiscoveryService, service)


@router.get("/", response_model=AvailableServerListResponse)
async def list_available_servers(
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
    include_maintenance: bool = False,
) -> AvailableServerListResponse:
    entries = await _service(request).list_available_servers(
        principal.user_id, include_maintenance=include_maintenance
    )
    # Every profile is listed on every route. Through the CDN, the ones that
    # cross it are listed at the CDN's port; the rest keep their own and will
    # simply not answer from a network that blocks this server's address --
    # which the app's per-protocol test shows, rather than hiding them. A
    # profile that fails here can work from another network, or on another
    # deployment of this server whose address is not blocked.
    route = cdn_route_for(request)
    apply_auth_response_headers(response)
    return AvailableServerListResponse(
        items=[
            AvailableServerItem(
                code=entry.code,
                display_name=entry.display_name,
                public_host=entry.public_host,
                maintenance=entry.maintenance,
                profiles=[
                    AvailableProfileItem(
                        code=profile.code,
                        display_name=profile.display_name,
                        protocol_id=profile.protocol_id,
                        protocol_code=profile.protocol_code,
                        ad_block=profile.ad_block,
                        required_port=(
                            CDN_PORT
                            if route and route.tunnel(profile.transport)
                            else profile.required_port
                        ),
                        requires_udp=profile.requires_udp,
                    )
                    for profile in entry.profiles
                ],
            )
            for entry in entries
        ]
    )
