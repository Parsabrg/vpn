"""Administrator topology routes: protocols, profiles, servers, and server state."""

from typing import cast
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from nebula_api.auth.admin_authorization import authorize_admin_mutation, require_admin_session
from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.models.operations import RECONCILIATION_OUTCOMES
from nebula_api.models.types import AdminRole
from nebula_api.provisioning.reconciliation import ReconciliationBusy, ReconciliationSummary
from nebula_api.security_status import SecurityStatusService
from nebula_api.topology_admin.schemas import (
    ProtocolListItem,
    ProtocolListResponse,
    ProtocolProfileListItem,
    ProtocolProfileListResponse,
    ReconcileNowRequest,
    ReconcileNowResponse,
    ReconciliationHistoryItem,
    ReconciliationHistoryResponse,
    ReconciliationSummaryItem,
    SecurityCheckItem,
    SecurityStatusResponse,
    SetVpnServerNameRequest,
    SetVpnServerStateRequest,
    TrafficSummaryItem,
    TrafficSummaryResponse,
    VpnServerHealthItem,
    VpnServerHealthListResponse,
    VpnServerListItem,
    VpnServerListResponse,
    VpnServerReconciliationItem,
    VpnServerReconciliationListResponse,
    VpnServerXrayHealthItem,
    VpnServerXrayHealthListResponse,
)
from nebula_api.topology_admin.service import TopologyAdminService

router = APIRouter(prefix="/v1/admin", tags=["admin-topology"])

_MUTATION_ROLES = frozenset({AdminRole.OWNER, AdminRole.OPERATOR})


def _service(request: Request) -> TopologyAdminService:
    service = getattr(request.app.state, "topology_admin_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Topology data is temporarily unavailable",
        )
    return cast(TopologyAdminService, service)


@router.get("/traffic-summary", response_model=TrafficSummaryResponse)
async def get_traffic_summary(request: Request, response: Response) -> TrafficSummaryResponse:
    await require_admin_session(request)
    entries = await _service(request).get_traffic_summary()
    apply_auth_response_headers(response)
    return TrafficSummaryResponse(
        items=[
            TrafficSummaryItem(
                protocol=entry.protocol,
                rx_bytes=str(entry.rx_bytes),
                tx_bytes=str(entry.tx_bytes),
                total_bytes=str(entry.rx_bytes + entry.tx_bytes),
                newest_collected_at=entry.newest_collected_at,
            )
            for entry in entries
        ]
    )


@router.get("/vpn-servers/xray-health", response_model=VpnServerXrayHealthListResponse)
async def get_vpn_server_xray_health(
    request: Request, response: Response
) -> VpnServerXrayHealthListResponse:
    await require_admin_session(request)
    entries = await _service(request).get_vpn_server_xray_health()
    apply_auth_response_headers(response)
    return VpnServerXrayHealthListResponse(
        items=[
            VpnServerXrayHealthItem(
                server_id=entry.server_id,
                code=entry.code,
                state=entry.state,
                observed_at=entry.observed_at,
                latency_ms=entry.latency_ms,
                agent_version=entry.agent_version,
                listener_up=entry.listener_up,
                error_code=entry.error_code,
            )
            for entry in entries
        ]
    )


@router.get("/reconciliation-history", response_model=ReconciliationHistoryResponse)
async def list_reconciliation_history(
    request: Request,
    response: Response,
    server_id: UUID | None = None,
    target_id: UUID | None = None,
    outcome: str | None = Query(default=None, pattern=f"^({'|'.join(RECONCILIATION_OUTCOMES)})$"),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ReconciliationHistoryResponse:
    await require_admin_session(request)
    page = await _service(request).list_reconciliation_history(
        server_id=server_id,
        target_id=target_id,
        outcome=outcome,
        limit=limit,
        offset=offset,
    )
    apply_auth_response_headers(response)
    return ReconciliationHistoryResponse(
        items=[
            ReconciliationHistoryItem(
                id=entry.id,
                server_id=entry.server_id,
                server_code=entry.server_code,
                target_kind=entry.target_kind,
                target_id=entry.target_id,
                desired_generation=entry.desired_generation,
                observed_generation=entry.observed_generation,
                outcome=entry.outcome,
                checked_at=entry.checked_at,
                error_code=entry.error_code,
            )
            for entry in page.items
        ],
        total=page.total,
        limit=limit,
        offset=offset,
    )


def _summary_item(summary: ReconciliationSummary) -> ReconciliationSummaryItem:
    return ReconciliationSummaryItem(
        checked=summary.checked,
        in_sync=summary.in_sync,
        repaired=summary.repaired,
        repair_failed=summary.repair_failed,
        ambiguous=summary.ambiguous,
        errored=summary.errored,
    )


@router.post("/reconciliation/run", response_model=ReconcileNowResponse)
async def reconcile_now(
    payload: ReconcileNowRequest, request: Request, response: Response
) -> ReconcileNowResponse:
    """The scheduled sweep, now: safe drift repaired, ambiguous drift recorded.

    No step-up: it can only do what the sweep would do on its own within 15
    minutes, and it never widens access.
    """

    principal = await authorize_admin_mutation(request, allowed_roles=_MUTATION_ROLES)
    try:
        result = await _service(request).reconcile_now(
            target_id=payload.target_id, admin_id=principal.admin_id, request_id=uuid4()
        )
    except ReconciliationBusy:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A reconciliation pass is already running; try again in a minute",
        ) from None
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Reconciliation is not available on this deployment",
        )
    wireguard, xray = result
    if payload.target_id is not None and wireguard.checked + xray.checked == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not a live WireGuard peer or Xray client on a running server",
        )
    apply_auth_response_headers(response)
    return ReconcileNowResponse(wireguard=_summary_item(wireguard), xray=_summary_item(xray))


@router.get("/vpn-servers/reconciliation", response_model=VpnServerReconciliationListResponse)
async def get_vpn_server_reconciliation(
    request: Request, response: Response
) -> VpnServerReconciliationListResponse:
    await require_admin_session(request)
    entries = await _service(request).get_vpn_server_reconciliation()
    apply_auth_response_headers(response)
    return VpnServerReconciliationListResponse(
        items=[
            VpnServerReconciliationItem(
                server_id=entry.server_id,
                code=entry.code,
                pending_provisions=entry.pending_provisions,
                pending_revocations=entry.pending_revocations,
                failed_records=entry.failed_records,
            )
            for entry in entries
        ]
    )


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


@router.get("/security-status", response_model=SecurityStatusResponse)
async def security_status(request: Request, response: Response) -> SecurityStatusResponse:
    """The security dashboard: only what this API can observe for itself."""

    await require_admin_session(request)
    service = getattr(request.app.state, "security_status_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security status is temporarily unavailable",
        )
    checks = await cast(SecurityStatusService, service).checks()
    apply_auth_response_headers(response)
    response.headers["Cache-Control"] = "no-store"
    return SecurityStatusResponse(
        checks=[
            SecurityCheckItem(
                key=check.key,
                label=check.label,
                status=check.status,
                detail=check.detail,
                observed_at=check.observed_at,
            )
            for check in checks
        ]
    )


@router.post("/vpn-servers/{server_id}/state", response_model=VpnServerListItem)
async def set_vpn_server_state(
    server_id: UUID,
    payload: SetVpnServerStateRequest,
    request: Request,
    response: Response,
) -> VpnServerListItem:
    """Active, maintenance or disabled; step-up, since it decides who can connect."""

    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    entry = await _service(request).set_vpn_server_state(
        server_id=server_id, state=payload.state, admin_id=principal.admin_id, request_id=uuid4()
    )
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found")
    apply_auth_response_headers(response)
    return VpnServerListItem(
        id=entry.id,
        code=entry.code,
        display_name=entry.display_name,
        state=entry.state,
        public_host=entry.public_host,
        maximum_devices=entry.maximum_devices,
    )


@router.post("/vpn-servers/{server_id}/name", response_model=VpnServerListItem)
async def set_vpn_server_name(
    server_id: UUID,
    payload: SetVpnServerNameRequest,
    request: Request,
    response: Response,
) -> VpnServerListItem:
    """Rename a server as the app shows it. Not step-up: it changes no access."""

    name = payload.display_name.strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="A name is required"
        )
    principal = await authorize_admin_mutation(request, allowed_roles=_MUTATION_ROLES)
    entry = await _service(request).set_vpn_server_name(
        server_id=server_id, display_name=name, admin_id=principal.admin_id, request_id=uuid4()
    )
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found")
    apply_auth_response_headers(response)
    return VpnServerListItem(
        id=entry.id,
        code=entry.code,
        display_name=entry.display_name,
        state=entry.state,
        public_host=entry.public_host,
        maximum_devices=entry.maximum_devices,
    )


@router.get("/vpn-servers/health", response_model=VpnServerHealthListResponse)
async def get_vpn_server_health(
    request: Request, response: Response
) -> VpnServerHealthListResponse:
    await require_admin_session(request)
    entries = await _service(request).get_vpn_server_health()
    apply_auth_response_headers(response)
    return VpnServerHealthListResponse(
        items=[
            VpnServerHealthItem(
                server_id=entry.server_id,
                code=entry.code,
                state=entry.state,
                observed_at=entry.observed_at,
                latency_ms=entry.latency_ms,
                agent_version=entry.agent_version,
                interface_up=entry.interface_up,
                peer_count=entry.peer_count,
            )
            for entry in entries
        ]
    )
