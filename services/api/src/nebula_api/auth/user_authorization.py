"""Reusable authenticated-user gate for new non-admin route modules.

`auth/user_routes.py`'s `/me` handler originally inlined this bearer-token
parsing directly (the only precedent before this module existed). This is
for every *new* authenticated-user route module added from this phase
onward (starting with `devices/`), so the same bearer-token contract isn't
re-implemented a second time; `/me` itself is refactored to use it too.
"""

from typing import NoReturn, cast

from fastapi import HTTPException, Request, status

from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.user_service import (
    AuthenticatedUser,
    AuthenticationRejected,
    UserAuthService,
)

_GENERIC_AUTH_DETAIL = "Authentication was not accepted"


def _service(request: Request) -> UserAuthService:
    service = getattr(request.app.state, "user_auth_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable",
        )
    return cast(UserAuthService, service)


def _raise_user_auth_error(error: Exception) -> NoReturn:
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


async def require_user_session(request: Request) -> AuthenticatedUser:
    """Any authenticated user. No origin/CSRF check -- bearer-token auth, no
    cookies involved, same rationale as the original inline /me check.

    `AuthenticatedUser.device_id` is the *login* device tied to the current
    session, not necessarily the device a caller's route is acting on --
    routes that mutate a specific device must take their own device_id
    parameter and verify ownership against `principal.user_id` themselves.
    """

    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme != "Bearer" or not token or " " in token:
        _raise_user_auth_error(AuthenticationRejected())
    try:
        return await _service(request).authenticate_access_token(token)
    except (AuthenticationRejected, AuthStateUnavailable) as error:
        _raise_user_auth_error(error)
