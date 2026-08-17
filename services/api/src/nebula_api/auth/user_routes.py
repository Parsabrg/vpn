"""Public user-authentication HTTP routes with a deliberately generic failure surface."""

import logging
from typing import Annotated, NoReturn, cast
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from nebula_api.auth.http import (
    apply_auth_response_headers,
    client_network_prefix,
    require_json_request,
)
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.schemas import (
    LogoutRequest,
    NeutralAcceptedResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RefreshRequest,
    TokenPairResponse,
    UserLoginRequest,
    UserPrincipalResponse,
)
from nebula_api.auth.user_authorization import require_user_session
from nebula_api.auth.user_service import (
    AuthenticatedUser,
    AuthenticationRateLimited,
    AuthenticationRejected,
    PasswordResetDelivery,
    UserAuthService,
)

router = APIRouter(prefix="/v1/auth", tags=["user-auth"])
_LOGGER = logging.getLogger(__name__)

_GENERIC_AUTH_DETAIL = "Authentication was not accepted"


def _service(request: Request) -> UserAuthService:
    service = getattr(request.app.state, "user_auth_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        )
    return cast(UserAuthService, service)


def _raise_public_auth_error(error: Exception) -> NoReturn:
    if isinstance(error, AuthenticationRateLimited):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_GENERIC_AUTH_DETAIL,
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from None
    if isinstance(error, AuthStateUnavailable):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        ) from None
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_GENERIC_AUTH_DETAIL,
        headers={"WWW-Authenticate": "Bearer"},
    ) from None


@router.post("/login", response_model=TokenPairResponse)
async def login(
    payload: UserLoginRequest, request: Request, response: Response
) -> TokenPairResponse:
    require_json_request(request)
    try:
        result = await _service(request).login(
            identifier=payload.identifier,
            password=payload.password.get_secret_value(),
            device_id=payload.device_id,
            device_name=payload.device_name,
            platform=payload.platform,
            client_version=payload.client_version,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_public_auth_error(error)
    apply_auth_response_headers(response)
    return TokenPairResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=result.access_expires_in,
    )


@router.post("/refresh", response_model=TokenPairResponse)
async def refresh(
    payload: RefreshRequest, request: Request, response: Response
) -> TokenPairResponse:
    require_json_request(request)
    try:
        result = await _service(request).refresh(
            refresh_token=payload.refresh_token.get_secret_value(),
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_public_auth_error(error)
    apply_auth_response_headers(response)
    return TokenPairResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=result.access_expires_in,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(payload: LogoutRequest, request: Request) -> Response:
    require_json_request(request)
    try:
        await _service(request).logout(
            refresh_token=payload.refresh_token.get_secret_value(),
            request_id=uuid4(),
        )
    except AuthStateUnavailable as error:
        _raise_public_auth_error(error)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    apply_auth_response_headers(response)
    return response


@router.get("/me", response_model=UserPrincipalResponse)
async def me(
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> UserPrincipalResponse:
    apply_auth_response_headers(response)
    return UserPrincipalResponse(
        user_id=principal.user_id,
        session_id=principal.session_id,
        device_id=principal.device_id,
    )


@router.post(
    "/password-reset/request",
    response_model=NeutralAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def request_password_reset(
    payload: PasswordResetRequest, request: Request, response: Response
) -> NeutralAcceptedResponse:
    require_json_request(request)
    dispatcher = cast(
        PasswordResetDelivery | None,
        getattr(request.app.state, "password_reset_delivery", None),
    )
    try:
        issue = await _service(request).request_password_reset(
            identifier=payload.identifier,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
            enable_delivery=dispatcher is not None,
        )
        if issue is not None and dispatcher is not None:
            try:
                await dispatcher(
                    recipient=issue.recipient,
                    token=issue.token,
                    delivery_id=issue.delivery_id,
                )
            except Exception:
                # Adapter failures must not reveal whether an identifier was eligible.
                # Delivery state is persisted separately for operational retries.
                _LOGGER.warning(
                    "Password-reset delivery adapter failed",
                    extra={"delivery_id": str(issue.delivery_id)},
                )
    except AuthenticationRateLimited as error:
        _raise_public_auth_error(error)
    except (AuthenticationRejected, AuthStateUnavailable):
        # Reset requests are intentionally neutral, including temporary delivery
        # failures. Operational state is recorded without reflecting identifiers.
        pass
    apply_auth_response_headers(response)
    return NeutralAcceptedResponse()


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset(
    payload: PasswordResetConfirmRequest, request: Request
) -> Response:
    require_json_request(request)
    try:
        await _service(request).confirm_password_reset(
            raw_token=payload.token.get_secret_value(),
            new_password=payload.new_password.get_secret_value(),
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_public_auth_error(error)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    apply_auth_response_headers(response)
    return response
