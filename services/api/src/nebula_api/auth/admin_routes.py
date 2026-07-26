"""Administrator password/MFA routes with strict cookie, origin, and CSRF handling."""

import hmac
from typing import NoReturn, cast
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status

from nebula_api.auth.admin_service import AdminAuthentication, AdminAuthService
from nebula_api.auth.http import (
    apply_auth_response_headers,
    client_network_prefix,
    discard_admin_csrf_replacement,
    require_allowed_origin,
    require_json_request,
    stage_admin_csrf_replacement,
)
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.schemas import (
    AdminChallengeResponse,
    AdminEnrollmentCompleteResponse,
    AdminEnrollmentConfirmRequest,
    AdminEnrollmentRequest,
    AdminEnrollmentResponse,
    AdminMfaRequest,
    AdminPasswordRequest,
    AdminRecoveryCodesResponse,
    AdminSessionResponse,
    AdminStepUpRequest,
)
from nebula_api.auth.user_service import AuthenticationRateLimited, AuthenticationRejected
from nebula_api.settings import Settings

router = APIRouter(prefix="/v1/admin/auth", tags=["admin-auth"])


def _service(request: Request) -> AdminAuthService:
    service = getattr(request.app.state, "admin_auth_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        )
    return cast(AdminAuthService, service)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _raise_auth_error(error: Exception) -> NoReturn:
    if isinstance(error, AuthenticationRateLimited):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Authentication was not accepted",
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from None
    if isinstance(error, AuthStateUnavailable):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        ) from None
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication was not accepted",
    ) from None


def _session_token(request: Request) -> str:
    token = request.cookies.get(_settings(request).admin_cookie_name)
    if not token:
        _raise_auth_error(AuthenticationRejected())
    return token


def _set_auth_cookies(
    response: Response,
    authentication: AdminAuthentication,
    settings: Settings,
) -> None:
    max_age = settings.admin_session_absolute_ttl_hours * 3_600
    response.set_cookie(
        settings.admin_cookie_name,
        authentication.session.session_token,
        max_age=max_age,
        secure=settings.admin_cookie_secure,
        httponly=True,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        settings.admin_csrf_cookie_name,
        authentication.session.csrf_token,
        max_age=max_age,
        secure=settings.admin_cookie_secure,
        httponly=False,
        samesite="strict",
        path="/",
    )
    response.headers["X-CSRF-Token"] = authentication.session.csrf_token


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        settings.admin_cookie_name,
        path="/",
        secure=settings.admin_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        settings.admin_csrf_cookie_name,
        path="/",
        secure=settings.admin_cookie_secure,
        httponly=False,
        samesite="strict",
    )


async def _protect_mutation(request: Request) -> tuple[str, str]:
    settings = _settings(request)
    require_allowed_origin(request, settings)
    require_json_request(request)
    session_token = _session_token(request)
    header_token = request.headers.get("x-csrf-token", "")
    cookie_token = request.cookies.get(settings.admin_csrf_cookie_name, "")
    if not header_token or not cookie_token or not hmac.compare_digest(header_token, cookie_token):
        _raise_auth_error(AuthenticationRejected())
    replacement = await _service(request).validate_and_rotate_csrf(
        session_token,
        header_token,
    )
    stage_admin_csrf_replacement(request, replacement)
    return session_token, replacement


@router.post("/login", response_model=AdminChallengeResponse)
async def password_login(
    payload: AdminPasswordRequest,
    request: Request,
    response: Response,
) -> AdminChallengeResponse:
    settings = _settings(request)
    require_allowed_origin(request, settings)
    require_json_request(request)
    try:
        challenge = await _service(request).password_challenge(
            identifier=payload.identifier,
            password=payload.password.get_secret_value(),
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    _clear_auth_cookies(response, settings)
    return AdminChallengeResponse(
        challenge=challenge.token,
        next_step=challenge.next_step,
        expires_in=challenge.expires_in_seconds,
    )


@router.post("/mfa/enrollment", response_model=AdminEnrollmentResponse)
async def start_enrollment(
    payload: AdminEnrollmentRequest,
    request: Request,
) -> AdminEnrollmentResponse:
    require_allowed_origin(request, _settings(request))
    require_json_request(request)
    try:
        enrollment = await _service(request).start_enrollment(
            challenge=payload.challenge.get_secret_value(),
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    return AdminEnrollmentResponse(
        challenge=enrollment.challenge,
        expires_in=enrollment.expires_in_seconds,
        secret=enrollment.base32_secret,
        provisioning_uri=enrollment.provisioning_uri,
    )


@router.post("/mfa/enrollment/confirm", response_model=AdminEnrollmentCompleteResponse)
async def confirm_enrollment(
    payload: AdminEnrollmentConfirmRequest,
    request: Request,
    response: Response,
) -> AdminEnrollmentCompleteResponse:
    settings = _settings(request)
    require_allowed_origin(request, settings)
    require_json_request(request)
    try:
        authentication = await _service(request).confirm_enrollment(
            challenge=payload.challenge.get_secret_value(),
            code=payload.code.get_secret_value(),
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
        principal = await _service(request).principal(authentication.session.session_token)
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    _set_auth_cookies(response, authentication, settings)
    return AdminEnrollmentCompleteResponse(
        admin_id=principal.admin_id,
        role=principal.role,
        csrf_token=authentication.session.csrf_token,
        step_up=False,
        recovery_codes=list(authentication.recovery_codes),
    )


@router.post("/mfa/verify", response_model=AdminSessionResponse)
async def verify_mfa(
    payload: AdminMfaRequest,
    request: Request,
    response: Response,
) -> AdminSessionResponse:
    settings = _settings(request)
    require_allowed_origin(request, settings)
    require_json_request(request)
    try:
        authentication = await _service(request).verify_mfa(
            challenge=payload.challenge.get_secret_value(),
            code=payload.code.get_secret_value(),
            method=payload.method,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
        principal = await _service(request).principal(authentication.session.session_token)
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    _set_auth_cookies(response, authentication, settings)
    return AdminSessionResponse(
        admin_id=principal.admin_id,
        role=principal.role,
        csrf_token=authentication.session.csrf_token,
        step_up=False,
    )


@router.get("/session", response_model=AdminSessionResponse)
async def current_session(request: Request) -> AdminSessionResponse:
    try:
        principal = await _service(request).principal(_session_token(request))
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    return AdminSessionResponse(
        admin_id=principal.admin_id,
        role=principal.role,
        step_up=principal.step_up,
    )


@router.post("/step-up", response_model=AdminSessionResponse)
async def step_up(
    payload: AdminStepUpRequest,
    request: Request,
    response: Response,
) -> AdminSessionResponse:
    try:
        session_token, _rotated_csrf = await _protect_mutation(request)
        authentication = await _service(request).step_up(
            session_token=session_token,
            code=payload.code.get_secret_value(),
            method=payload.method,
            network_prefix=client_network_prefix(request),
            request_id=uuid4(),
        )
        principal = await _service(request).principal(authentication.session.session_token)
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    _set_auth_cookies(response, authentication, _settings(request))
    return AdminSessionResponse(
        admin_id=principal.admin_id,
        role=principal.role,
        csrf_token=authentication.session.csrf_token,
        step_up=True,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request) -> Response:
    try:
        session_token, _rotated_csrf = await _protect_mutation(request)
        await _service(request).logout(session_token, request_id=uuid4())
        discard_admin_csrf_replacement(request)
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_auth_cookies(response, _settings(request))
    apply_auth_response_headers(response)
    return response


@router.post("/recovery-codes/rotate", response_model=AdminRecoveryCodesResponse)
async def rotate_recovery_codes(
    request: Request,
    response: Response,
) -> AdminRecoveryCodesResponse:
    try:
        session_token, replacement_csrf = await _protect_mutation(request)
        codes = await _service(request).rotate_recovery_codes(
            session_token=session_token,
            request_id=uuid4(),
        )
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_auth_error(error)
    response.set_cookie(
        _settings(request).admin_csrf_cookie_name,
        replacement_csrf,
        max_age=_settings(request).admin_session_absolute_ttl_hours * 3_600,
        secure=_settings(request).admin_cookie_secure,
        httponly=False,
        samesite="strict",
        path="/",
    )
    response.headers["X-CSRF-Token"] = replacement_csrf
    return AdminRecoveryCodesResponse(recovery_codes=list(codes))
