"""Admin-facing user listing, detail, and step-up-gated lifecycle mutation routes."""

from typing import NoReturn, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from nebula_api.auth.admin_authorization import authorize_admin_mutation, require_admin_session
from nebula_api.auth.http import apply_auth_response_headers, client_network_prefix
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.models.types import AdminRole
from nebula_api.user_management.schemas import (
    DeviceListItem,
    UserDetailResponse,
    UserListItem,
    UserListResponse,
    UserSessionListItem,
)
from nebula_api.user_management.service import (
    DeviceSummary,
    UserDetail,
    UserManagementRateLimited,
    UserManagementRejected,
    UserManagementService,
    UserSessionSummary,
    UserSummary,
)

router = APIRouter(prefix="/v1/admin/users", tags=["admin-users"])

_GENERIC_DETAIL = "Request was not accepted"
_MUTATION_ROLES = frozenset({AdminRole.OWNER, AdminRole.OPERATOR})


def _service(request: Request) -> UserManagementService:
    service = getattr(request.app.state, "user_management_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User management is temporarily unavailable",
        )
    return cast(UserManagementService, service)


def _raise_user_management_error(error: Exception) -> NoReturn:
    if isinstance(error, UserManagementRateLimited):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_GENERIC_DETAIL,
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from None
    if isinstance(error, AuthStateUnavailable):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User management is temporarily unavailable",
        ) from None
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_GENERIC_DETAIL) from None


def _to_user_item(summary: UserSummary) -> UserListItem:
    return UserListItem(
        id=summary.id,
        email=summary.email,
        username=summary.username,
        state=summary.state.value,
        device_limit=summary.device_limit,
        expires_at=summary.expires_at,
        activated_at=summary.activated_at,
        disabled_at=summary.disabled_at,
        created_at=summary.created_at,
    )


def _to_device_item(summary: DeviceSummary) -> DeviceListItem:
    return DeviceListItem(
        id=summary.id,
        name=summary.name,
        platform=summary.platform,
        client_version=summary.client_version,
        state=summary.state.value,
        revoked_at=summary.revoked_at,
    )


def _to_session_item(summary: UserSessionSummary) -> UserSessionListItem:
    return UserSessionListItem(
        id=summary.id,
        device_id=summary.device_id,
        state=summary.state.value,
        expires_at=summary.expires_at,
        last_seen_at=summary.last_seen_at,
        revoked_at=summary.revoked_at,
    )


def _to_detail(detail: UserDetail) -> UserDetailResponse:
    return UserDetailResponse(
        user=_to_user_item(detail.user),
        devices=[_to_device_item(item) for item in detail.devices],
        sessions=[_to_session_item(item) for item in detail.sessions],
    )


@router.get("/", response_model=UserListResponse)
async def list_users(
    request: Request,
    response: Response,
    state: str | None = None,
    email_prefix: str | None = None,
    username_prefix: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> UserListResponse:
    await require_admin_session(request)
    page = await _service(request).list_users(
        state=state,
        email_prefix=email_prefix,
        username_prefix=username_prefix,
        limit=limit,
        offset=offset,
    )
    apply_auth_response_headers(response)
    return UserListResponse(
        items=[_to_user_item(item) for item in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get("/{user_id}", response_model=UserDetailResponse)
async def get_user(user_id: UUID, request: Request, response: Response) -> UserDetailResponse:
    await require_admin_session(request)
    detail = await _service(request).get_user_detail(user_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_GENERIC_DETAIL)
    apply_auth_response_headers(response)
    return _to_detail(detail)


@router.post("/{user_id}/disable", response_model=UserListItem)
async def disable_user(user_id: UUID, request: Request, response: Response) -> UserListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).disable_user(
            user_id=user_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (UserManagementRejected, AuthStateUnavailable) as error:
        _raise_user_management_error(error)
    apply_auth_response_headers(response)
    return _to_user_item(summary)


@router.post("/{user_id}/reactivate", response_model=UserListItem)
async def reactivate_user(user_id: UUID, request: Request, response: Response) -> UserListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).reactivate_user(
            user_id=user_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (UserManagementRejected, AuthStateUnavailable) as error:
        _raise_user_management_error(error)
    apply_auth_response_headers(response)
    return _to_user_item(summary)


@router.post("/{user_id}/devices/{device_id}/revoke", response_model=DeviceListItem)
async def revoke_device(
    user_id: UUID, device_id: UUID, request: Request, response: Response
) -> DeviceListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).revoke_device(
            user_id=user_id,
            device_id=device_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (UserManagementRejected, AuthStateUnavailable) as error:
        _raise_user_management_error(error)
    apply_auth_response_headers(response)
    return _to_device_item(summary)


@router.post("/{user_id}/sessions/{session_id}/revoke", response_model=UserSessionListItem)
async def revoke_session(
    user_id: UUID, session_id: UUID, request: Request, response: Response
) -> UserSessionListItem:
    principal = await authorize_admin_mutation(
        request, allowed_roles=_MUTATION_ROLES, require_step_up=True
    )
    try:
        summary = await _service(request).revoke_session(
            user_id=user_id,
            session_id=session_id,
            admin_id=principal.admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (UserManagementRejected, AuthStateUnavailable) as error:
        _raise_user_management_error(error)
    apply_auth_response_headers(response)
    return _to_session_item(summary)
