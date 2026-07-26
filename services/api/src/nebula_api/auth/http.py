"""HTTP-facing authentication safeguards shared by both identity realms."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware

from nebula_api.settings import Settings

AUTH_CACHE_CONTROL = "no-store"
AUTH_REFERRER_POLICY = "no-referrer"
_ADMIN_CSRF_REPLACEMENT_STATE = "_nebula_admin_csrf_replacement"


def install_auth_http_safeguards(application: FastAPI, settings: Settings) -> None:
    """Install exact-origin CORS and a redacted validation-error handler."""

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origin_values),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
        expose_headers=["X-CSRF-Token"],
    )

    @application.middleware("http")
    async def auth_response_policy(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        _apply_staged_admin_csrf(request, response, settings)
        if request.url.path.startswith(("/v1/auth", "/v1/admin/auth")):
            apply_auth_response_headers(response)
        return response

    @application.exception_handler(RequestValidationError)
    async def redacted_validation_error(
        _request: Request, error: RequestValidationError
    ) -> JSONResponse:
        details = [
            {
                "type": item.get("type", "validation_error"),
                "loc": list(item.get("loc", ())),
                "msg": item.get("msg", "Invalid request"),
            }
            for item in error.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": details},
            headers={
                "Cache-Control": AUTH_CACHE_CONTROL,
                "Referrer-Policy": AUTH_REFERRER_POLICY,
            },
        )


def apply_auth_response_headers(response: Response) -> None:
    """Prevent credentials and auth outcomes from entering browser caches/referrers."""

    response.headers["Cache-Control"] = AUTH_CACHE_CONTROL
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = AUTH_REFERRER_POLICY


def stage_admin_csrf_replacement(request: Request, token: str) -> None:
    """Preserve a consumed one-time CSRF replacement across later error responses."""

    setattr(request.state, _ADMIN_CSRF_REPLACEMENT_STATE, token)


def discard_admin_csrf_replacement(request: Request) -> None:
    """Prevent middleware from restoring CSRF state after a successful logout."""

    setattr(request.state, _ADMIN_CSRF_REPLACEMENT_STATE, None)


def _apply_staged_admin_csrf(request: Request, response: Response, settings: Settings) -> None:
    replacement = getattr(request.state, _ADMIN_CSRF_REPLACEMENT_STATE, None)
    if type(replacement) is not str or response.headers.get("x-csrf-token"):
        return
    response.set_cookie(
        settings.admin_csrf_cookie_name,
        replacement,
        max_age=settings.admin_session_absolute_ttl_hours * 3_600,
        secure=settings.admin_cookie_secure,
        httponly=False,
        samesite="strict",
        path="/",
    )
    response.headers["X-CSRF-Token"] = replacement


def require_json_request(request: Request) -> None:
    """Reject form and text/plain submissions on credential-bearing endpoints."""

    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="application/json is required",
        )


def require_allowed_origin(request: Request, settings: Settings) -> None:
    """Require an exact trusted Origin for unsafe cookie-authenticated requests."""

    origin = request.headers.get("origin")
    if origin is None or origin not in settings.allowed_origin_values:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Request denied")


def client_network_prefix(request: Request) -> str:
    """Return a coarse prefix from the socket peer, ignoring spoofable forwarding headers."""

    if request.client is None:
        return "unknown"
    try:
        address = ip_address(request.client.host)
    except ValueError:
        return "unknown"
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if isinstance(address, IPv4Address):
        return str(IPv4Network((address, 24), strict=False))
    return str(IPv6Network((address, 64), strict=False))
