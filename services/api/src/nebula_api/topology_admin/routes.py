"""Read-only administrator topology routes (protocols, profiles, servers)."""

from typing import cast

from fastapi import APIRouter, HTTPException, Request, Response, status

from nebula_api.auth.admin_authorization import require_admin_session
from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.topology_admin.schemas import (
    ProtocolListItem,
    ProtocolListResponse,
    ProtocolProfileListItem,
    ProtocolProfileListResponse,
    VpnServerListItem,
    VpnServerListResponse,
)
from nebula_api.topology_admin.service import TopologyAdminService

router = APIRouter(prefix="/v1/admin", tags=["admin-topology"])


def _service(request: Request) -> TopologyAdminService:
    service = getattr(request.app.state, "topology_admin_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Topology data is temporarily unavailable",
        )
    return cast(TopologyAdminService, service)


@router.get("/protocols", response_model=ProtocolListResponse)
async def list_protocols(request: Request, response: Response) -> ProtocolListResponse:
    await require_admin_session(request)
    entries = await _service(request).list_protocols()
    apply_auth_response_headers(response)
    return ProtocolListResponse(
        items=[
            ProtocolListItem(
                id=entry.id,
                code=entry.code,
                display_name=entry.display_name,
                engine=entry.engine,
                is_user_selectable=entry.is_user_selectable,
            )
            for entry in entries
        ]
    )


@router.get("/protocol-profiles", response_model=ProtocolProfileListResponse)
async def list_protocol_profiles(
    request: Request, response: Response
) -> ProtocolProfileListResponse:
    await require_admin_session(request)
    entries = await _service(request).list_protocol_profiles()
    apply_auth_response_headers(response)
    return ProtocolProfileListResponse(
        items=[
            ProtocolProfileListItem(
                id=entry.id,
                protocol_id=entry.protocol_id,
                code=entry.code,
                version=entry.version,
                display_name=entry.display_name,
                state=entry.state,
                transport=entry.transport,
                transport_security=entry.transport_security,
                requires_udp=entry.requires_udp,
                is_full_tunnel=entry.is_full_tunnel,
            )
            for entry in entries
        ]
    )


@router.get("/vpn-servers", response_model=VpnServerListResponse)
async def list_vpn_servers(request: Request, response: Response) -> VpnServerListResponse:
    await require_admin_session(request)
    entries = await _service(request).list_vpn_servers()
    apply_auth_response_headers(response)
    return VpnServerListResponse(
        items=[
            VpnServerListItem(
                id=entry.id,
                code=entry.code,
                display_name=entry.display_name,
                state=entry.state,
                public_host=entry.public_host,
                maximum_devices=entry.maximum_devices,
            )
            for entry in entries
        ]
    )
