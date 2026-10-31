"""Account-request submission, administrator review, and activation routes."""

from typing import NoReturn, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status

from nebula_api.accounts.schemas import (
    AccountRequestDecisionRequest,
    AccountRequestListItem,
    AccountRequestListResponse,
    AccountRequestSubmitRequest,
    ActivationConfirmRequest,
)
from nebula_api.accounts.service import (
    AccountRequestConflict,
    AccountRequestRateLimited,
    AccountRequestRejected,
    AccountRequestService,
    AccountRequestSummary,
)
from nebula_api.auth.admin_authorization import (
    authorize_admin_mutation,
    require_admin_session,
)
from nebula_api.auth.admin_service import AdminAuthService
from nebula_api.auth.http import (
    apply_auth_response_headers,
    client_network_prefix,
    require_json_request,
)
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.schemas import NeutralAcceptedResponse
from nebula_api.auth.user_service import AuthenticationRejected
from nebula_api.models.types import AdminRole
from nebula_api.settings import Settings

router = APIRouter(prefix="/v1/account-requests", tags=["account-requests"])
admin_router = APIRouter(prefix="/v1/admin/account-requests", tags=["admin-account-requests"])

_GENERIC_DETAIL = "Request was not accepted"
_REVIEW_ROLES = frozenset({AdminRole.OWNER, AdminRole.OPERATOR})


def _service(request: Request) -> AccountRequestService:
    service = getattr(request.app.state, "account_request_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Account requests are temporarily unavailable",
        )
    return cast(AccountRequestService, service)


def _admin_auth_service(request: Request) -> AdminAuthService:
    service = getattr(request.app.state, "admin_auth_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        )
    return cast(AdminAuthService, service)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _raise_account_request_error(error: Exception) -> NoReturn:
    if isinstance(error, AccountRequestRateLimited):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_GENERIC_DETAIL,
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from None
    if isinstance(error, AccountRequestConflict):
        # Admin-only route, so naming the clash tells no outsider anything.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from None
    if isinstance(error, AuthStateUnavailable):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Account requests are temporarily unavailable",
        ) from None
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_GENERIC_DETAIL) from None


def _raise_admin_auth_error(error: Exception) -> NoReturn:
    if isinstance(error, AuthStateUnavailable):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        ) from None
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication was not accepted",
    ) from None


def _to_item(summary: AccountRequestSummary) -> AccountRequestListItem:
    return AccountRequestListItem(
        id=summary.id,
        email=summary.email,
        username=summary.username,
        state=summary.state,
        created_at=summary.created_at,
    )


async def _authorize_reviewer(request: Request) -> UUID:
    """Enforce origin/CSRF/session and a review-capable role; return the admin id.

    Delegates rather than repeating the checks: this was a line-for-line copy
    of authorize_admin_mutation, which meant every hardening applied to admin
    mutations had to be remembered here too, and silently was not.
    """

    principal = await authorize_admin_mutation(request, allowed_roles=_REVIEW_ROLES)
    return principal.admin_id


@router.post(
    "/",
    response_model=NeutralAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_request(
    payload: AccountRequestSubmitRequest, request: Request, response: Response
) -> NeutralAcceptedResponse:
    require_json_request(request)
    try:
        await _service(request).submit_request(
            email=payload.email,
            username=payload.username,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except AccountRequestRateLimited as error:
        _raise_account_request_error(error)
    except AuthStateUnavailable:
        # Submission is intentionally neutral: even a transient dependency
        # outage must not distinguish itself from an ordinary accepted request.
        pass
    apply_auth_response_headers(response)
    return NeutralAcceptedResponse()


@router.post("/activate", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_activation(payload: ActivationConfirmRequest, request: Request) -> Response:
    require_json_request(request)
    try:
        await _service(request).confirm_activation(
            raw_token=payload.token.get_secret_value(),
            new_password=payload.new_password.get_secret_value(),
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AccountRequestRejected, AuthStateUnavailable) as error:
        _raise_account_request_error(error)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    apply_auth_response_headers(response)
    return response


@admin_router.get("/", response_model=AccountRequestListResponse)
async def list_pending(request: Request, response: Response) -> AccountRequestListResponse:
    await require_admin_session(request)
    try:
        items = await _service(request).list_pending()
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_admin_auth_error(error)
    apply_auth_response_headers(response)
    return AccountRequestListResponse(items=[_to_item(item) for item in items])


@admin_router.post("/{account_request_id}/approve", response_model=AccountRequestListItem)
async def approve(
    account_request_id: UUID, request: Request, response: Response
) -> AccountRequestListItem:
    admin_id = await _authorize_reviewer(request)
    try:
        summary = await _service(request).approve(
            account_request_id=account_request_id,
            admin_id=admin_id,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AccountRequestRejected, AuthStateUnavailable) as error:
        _raise_account_request_error(error)
    apply_auth_response_headers(response)
    return _to_item(summary)


@admin_router.post("/{account_request_id}/reject", response_model=AccountRequestListItem)
async def reject(
    account_request_id: UUID,
    payload: AccountRequestDecisionRequest,
    request: Request,
    response: Response,
) -> AccountRequestListItem:
    admin_id = await _authorize_reviewer(request)
    try:
        summary = await _service(request).reject(
            account_request_id=account_request_id,
            admin_id=admin_id,
            reason=payload.reason,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AccountRequestRejected, AuthStateUnavailable) as error:
        _raise_account_request_error(error)
    apply_auth_response_headers(response)
    return _to_item(summary)
