"""Every address this API can be reached at, told to clients that can reach it.

A client only knows the addresses that were compiled into it. When one is
blocked -- as this server's own was -- an address added afterwards cannot help
anyone who has not installed a new build, which is the slowest possible way to
answer a block: exactly the position every 0.1.10 install was left in.

So a client that can reach the API asks it where else it can be reached, and
keeps the answer for when it cannot. Adding an address then becomes a change
to `NEBULA_API_ROUTES` that reaches installed apps on their next successful
request, instead of a release.

Session-gated on purpose. These addresses are a censor's shopping list; they
should cost an account to read, not a single unauthenticated GET. A client
that cannot reach the API at all learns nothing new -- it is already holding
the list from the last time it could.
"""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request, Response

from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.auth.schemas import AuthModel
from nebula_api.auth.user_authorization import require_user_session
from nebula_api.auth.user_service import AuthenticatedUser
from nebula_api.settings import Settings

router = APIRouter(prefix="/v1/routes", tags=["routes"])


class ApiRouteListResponse(AuthModel):
    routes: list[str]


def configured_routes(settings: Settings) -> list[str]:
    """`NEBULA_API_ROUTES`, in order, https only, without duplicates.

    Anything that is not an https URL is dropped rather than refused: a
    typo in one entry must not take the whole list -- and with it a client's
    only way to learn about the others -- out of service.
    """

    seen: list[str] = []
    for entry in settings.api_routes.split(","):
        route = entry.strip().rstrip("/")
        if route.startswith("https://") and route not in seen:
            seen.append(route)
    return seen


@router.get("/", response_model=ApiRouteListResponse)
async def list_api_routes(
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> ApiRouteListResponse:
    del principal  # Required for the session gate; the list is the same for everyone.
    settings = cast(Settings, request.app.state.settings)
    apply_auth_response_headers(response)
    return ApiRouteListResponse(routes=configured_routes(settings))
