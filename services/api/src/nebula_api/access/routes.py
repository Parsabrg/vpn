"""Admin-facing protocol-permission and server-assignment listing and
step-up-gated grant/revoke mutation routes."""

from typing import NoReturn, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from nebula_api.access.schemas import (
    AssignmentListItem,
    AssignmentListResponse,
    PermissionListItem,
    PermissionListResponse,
    UserAssignmentListItem,
    UserAssignmentListResponse,
    UserPermissionListItem,
    UserPermissionListResponse,
)
from nebula_api.access.service import (
    AccessRateLimited,
    AccessRejected,
    AccessService,
    AssignmentListEntry,
    AssignmentSummary,
    PermissionListEntry,
    PermissionSummary,
)
from nebula_api.auth.admin_authorization import authorize_admin_mutation, require_admin_session
from nebula_api.auth.http import apply_auth_response_headers, client_network_prefix
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.models.types import AdminRole

router = APIRouter(prefix="/v1/admin", tags=["admin-access"])

_GENERIC_DETAIL = "Request was not accepted"
_MUTATION_ROLES = frozenset({AdminRole.OWNER, AdminRole.OPERATOR})


def _service(request: Request) -> AccessService:
    service = getattr(request.app.state, "access_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Access management is temporarily unavailable",
        )
    return cast(AccessService, service)


def _raise_access_error(error: Exception) -> NoReturn:
    if isinstance(error, AccessRateLimited):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_GENERIC_DETAIL,
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from None
    if isinstance(error, AuthStateUnavailable):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Access management is temporarily unavailable",
        ) from None
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_GENERIC_DETAIL) from None


def _to_permission_item(summary: PermissionSummary) -> UserPermissionListItem:
    return UserPermissionListItem(
        id=summary.id,
        protocol_profile_id=summary.protocol_profile_id,
        profile_code=summary.profile_code,
        profile_display_name=summary.profile_display_name,
        state=summary.state,
        granted_by_admin_id=summary.granted_by_admin_id,
        granted_at=summary.granted_at,
        expires_at=summary.expires_at,
        revoked_at=summary.revoked_at,
    )


def _to_assignment_item(summary: AssignmentSummary) -> UserAssignmentListItem:
    return UserAssignmentListItem(
        id=summary.id,
        vpn_server_id=summary.vpn_server_id,
        server_code=summary.server_code,
        server_display_name=summary.server_display_name,
        state=summary.state,
        assigned_by_admin_id=summary.assigned_by_admin_id,
        assigned_at=summary.assigned_at,
        expires_at=summary.expires_at,
        revoked_at=summary.revoked_at,
    )


def _to_permission_list_item(entry: PermissionListEntry) -> PermissionListItem:
    return PermissionListItem(
        id=entry.id,
        protocol_profile_id=entry.protocol_profile_id,
        profile_code=entry.profile_code,
        profile_display_name=entry.profile_display_name,
        state=entry.state,
        granted_by_admin_id=entry.granted_by_admin_id,
        granted_at=entry.granted_at,
        expires_at=entry.expires_at,
        revoked_at=entry.revoked_at,
        user_id=entry.user_id,
        user_email=entry.user_email,
    )


def _to_assignment_list_item(entry: AssignmentListEntry) -> AssignmentListItem:
    return AssignmentListItem(
        id=entry.id,
        vpn_server_id=entry.vpn_server_id,
        server_code=entry.server_code,
        server_display_name=entry.server_display_name,
        state=entry.state,
        assigned_by_admin_id=entry.assigned_by_admin_id,
        assigned_at=entry.assigned_at,
        expires_at=entry.expires_at,
        revoked_at=entry.revoked_at,
        user_id=entry.user_id,
        user_email=entry.user_email,
    )


@router.get("/permissions", response_model=PermissionListResponse)
async def list_permissions(
    request: Request,
    response: Response,
    state: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> PermissionListResponse:
    await require_admin_session(request)
    page = await _service(request).list_all_permissions(state=state, limit=limit, offset=offset)
    apply_auth_response_headers(response)
    return PermissionListResponse(
        items=[_to_permission_list_item(item) for item in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get("/assignments", response_model=AssignmentListResponse)
async def list_assignments(
    request: Request,
    response: Response,
    state: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AssignmentListResponse:
    await require_admin_session(request)
    page = await _service(request).list_all_assignments(state=state, limit=limit, offset=offset)
    apply_auth_response_headers(response)
    return AssignmentListResponse(
        items=[_to_assignment_list_item(item) for item in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get("/users/{user_id}/permissions", response_model=UserPermissionListResponse)
async def list_user_permissions(
    user_id: UUID, request: Request, response: Response
) -> UserPermissionListResponse:
    await require_admin_session(request)
    items = await _service(request).list_user_permissions(user_id)
    apply_auth_response_headers(response)
    return UserPermissionListResponse(items=[_to_permission_item(item) for item in items])


@router.post(
    "/users/{user_id}/permissions/{protocol_profile_id}/grant",
    response_model=UserPermissionListItem,
)
async def grant_permission(
    user_id: UUID, protocol_profile_id: UUID, request: Request, response: Response
) -> UserPermissionListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).grant_permission(
            user_id=user_id,
            protocol_profile_id=protocol_profile_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AccessRejected, AuthStateUnavailable) as error:
        _raise_access_error(error)
    apply_auth_response_headers(response)
    return _to_permission_item(summary)


@router.post(
    "/users/{user_id}/permissions/{protocol_profile_id}/revoke",
    response_model=UserPermissionListItem,
)
async def revoke_permission(
    user_id: UUID, protocol_profile_id: UUID, request: Request, response: Response
) -> UserPermissionListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).revoke_permission(
            user_id=user_id,
            protocol_profile_id=protocol_profile_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AccessRejected, AuthStateUnavailable) as error:
        _raise_access_error(error)
    apply_auth_response_headers(response)
    return _to_permission_item(summary)


@router.get("/users/{user_id}/assignments", response_model=UserAssignmentListResponse)
async def list_user_assignments(
    user_id: UUID, request: Request, response: Response
) -> UserAssignmentListResponse:
    await require_admin_session(request)
    items = await _service(request).list_user_assignments(user_id)
    apply_auth_response_headers(response)
    return UserAssignmentListResponse(items=[_to_assignment_item(item) for item in items])


@router.post(
    "/users/{user_id}/assignments/{vpn_server_id}/assign",
    response_model=UserAssignmentListItem,
)
async def assign_server(
    user_id: UUID, vpn_server_id: UUID, request: Request, response: Response
) -> UserAssignmentListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).assign_server(
            user_id=user_id,
            vpn_server_id=vpn_server_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AccessRejected, AuthStateUnavailable) as error:
        _raise_access_error(error)
    apply_auth_response_headers(response)
    return _to_assignment_item(summary)


@router.post(
    "/users/{user_id}/assignments/{vpn_server_id}/revoke",
    response_model=UserAssignmentListItem,
)
async def revoke_assignment(
    user_id: UUID, vpn_server_id: UUID, request: Request, response: Response
) -> UserAssignmentListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).revoke_assignment(
            user_id=user_id,
            vpn_server_id=vpn_server_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AccessRejected, AuthStateUnavailable) as error:
        _raise_access_error(error)
    apply_auth_response_headers(response)
    return _to_assignment_item(summary)
