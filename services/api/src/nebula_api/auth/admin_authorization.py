"""Reusable admin session/CSRF/role gates for new admin route modules.

`auth/admin_routes.py` and `accounts/routes.py` each keep their own private
copy of this logic (an established convention in this codebase — see the
duplicated `_service`/`_raise_*_error` helpers in those two modules). This
module exists for every *new* admin route module added from this phase
onward, so the same origin/CSRF/step-up contract isn't re-implemented a
third, fourth, and fifth time; it does not touch either existing module.
"""

import hmac
from typing import NoReturn, cast

from fastapi import HTTPException, Request, status

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import (
    require_allowed_origin,
    require_json_request,
    stage_admin_csrf_replacement,
)
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.user_service import AuthenticationRejected
from nebula_api.models.types import AdminRole
from nebula_api.settings import Settings

STEP_UP_REQUIRED_DETAIL = "step_up_required"


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


async def require_admin_session(request: Request) -> AdminPrincipal:
    """Any authenticated admin, any role. No origin/CSRF check (GET-safe)."""

    settings = _settings(request)
    session_token = request.cookies.get(settings.admin_cookie_name, "")
    if not session_token:
        _raise_admin_auth_error(AuthenticationRejected())
    try:
        return await _admin_auth_service(request).principal(session_token)
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_admin_auth_error(error)


async def authorize_admin_mutation(
    request: Request,
    *,
    allowed_roles: frozenset[AdminRole] = frozenset(AdminRole),
    require_step_up: bool = False,
) -> AdminPrincipal:
    """Origin + JSON + CSRF-rotate + role gate, optionally requiring step-up MFA.

    Raises 403 with detail "step_up_required" when `require_step_up` is True
    and the admin's current session has not freshly stepped up, so the
    frontend can distinguish this from a generic denial and prompt for MFA
    rather than showing an opaque failure.
    """

    settings = _settings(request)
    require_allowed_origin(request, settings)
    require_json_request(request)
    session_token = request.cookies.get(settings.admin_cookie_name, "")
    if not session_token:
        _raise_admin_auth_error(AuthenticationRejected())
    header_token = request.headers.get("x-csrf-token", "")
    cookie_token = request.cookies.get(settings.admin_csrf_cookie_name, "")
    if not header_token or not cookie_token or not hmac.compare_digest(header_token, cookie_token):
        _raise_admin_auth_error(AuthenticationRejected())
    admin_service = _admin_auth_service(request)
    try:
        replacement = await admin_service.validate_and_rotate_csrf(session_token, header_token)
        principal = await admin_service.principal(session_token)
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_admin_auth_error(error)
    if principal.role not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Request denied")
    if require_step_up and not principal.step_up:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=STEP_UP_REQUIRED_DETAIL)
    stage_admin_csrf_replacement(request, replacement)
    return principal
