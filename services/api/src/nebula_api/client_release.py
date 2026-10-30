"""The newest client release, for apps that cannot ask GitHub.

The apps look for updates on the repository's GitHub releases, and while the
repository is private GitHub answers "not found" -- so installs sat on old
versions with nothing telling them otherwise (a Windows PC was on 0.1.20
when 0.1.24 was current). This hands signed-in apps the version named in
`NEBULA_CLIENT_LATEST_VERSION`, set when a release is published.

Session-gated like /v1/routes: it costs nothing to keep it to accounts, and
every unauthenticated route is attack surface.
"""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request, Response

from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.auth.schemas import AuthModel
from nebula_api.auth.user_authorization import require_user_session
from nebula_api.auth.user_service import AuthenticatedUser
from nebula_api.settings import Settings

router = APIRouter(prefix="/v1/client", tags=["client"])


class ClientReleaseResponse(AuthModel):
    # None when no version is configured: the app then offers nothing.
    version: str | None


@router.get("/release", response_model=ClientReleaseResponse)
async def latest_client_release(
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> ClientReleaseResponse:
    del principal  # Required for the session gate; the answer is the same for everyone.
    settings = cast(Settings, request.app.state.settings)
    apply_auth_response_headers(response)
    return ClientReleaseResponse(version=settings.client_latest_version or None)
