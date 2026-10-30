"""Every route either authorizes or is on the public list, by construction.

Authorization here is a call at the top of each handler, not a router-level
dependency, so a new route is unprotected by omission -- nothing fails, no
test breaks, and the endpoint is simply open. The existing authorization
tests exercise the helpers in isolation and cannot see that: they prove the
lock works, not that it was fitted to every door.

This walks the real application's route table and asserts each handler
reaches one of the authorization entry points, with public routes named
explicitly below. Adding a route without either fails here, which is the
point -- the reviewer has to make the choice deliberately rather than by
forgetting.

Source inspection rather than unauthenticated calls: FastAPI validates path
and body parameters before the handler runs, so an unprotected route with a
required body answers 422 instead of 200, and a behavioural check would read
that as protected.
"""

import ast
import inspect
import textwrap
from collections.abc import Callable, Iterable, Iterator

from fastapi.routing import APIRoute, _IncludedRouter
from starlette.routing import BaseRoute

from nebula_api.main import create_app
from nebula_api.settings import Settings

# The only three ways a route may authorize. Anything else is a fourth copy
# of the logic that has to be kept in sync by hand -- accounts/routes.py had
# exactly that, and it is now gone.
AUTHORIZATION_CALLS = frozenset(
    {
        "require_admin_session",
        "authorize_admin_mutation",
        "require_user_session",
    }
)

# The session primitives underneath those helpers. Only the auth module's own
# routes should reach these: it implements authentication, so it cannot use
# the helpers built on top of itself without circularity. A feature route
# calling these directly is a fourth copy of the logic and should use a helper.
AUTHORIZATION_PRIMITIVES = frozenset({"principal", "validate_and_rotate_csrf"})

# Routes that are deliberately reachable without credentials, each with the
# reason. Anything not listed must authorize. Keep this list short and make
# adding to it uncomfortable: every entry is public attack surface.
PUBLIC_ROUTES = {
    ("/healthz", "GET"): "liveness probe; reports status and version only",
    ("/readyz", "GET"): "readiness probe; reports status and version only",
    ("/metrics", "GET"): "Prometheus counters by route template; nginx answers it with 404 "
    "from outside, so only the host's loopback reads it",
    ("/v1/pairing", "GET"): "read before any account exists, to check the pairing link; "
    "holds only the deployment's name, identity and CA, which the link already names -- "
    "server addresses and other routes stay behind sign-in",
    ("/v1/auth/login", "POST"): "issues the session, so cannot require one",
    ("/v1/auth/refresh", "POST"): "the refresh token in the request is the credential",
    ("/v1/auth/logout", "POST"): "clears a session; safe and useful without a valid one",
    (
        "/v1/auth/password-reset/request",
        "POST",
    ): "the user cannot sign in, which is why they are here",
    ("/v1/auth/password-reset/confirm", "POST"): "the reset token is the credential",
    ("/v1/admin/auth/login", "POST"): "issues the admin session",
    ("/v1/admin/auth/logout", "POST"): "clears a session; safe without a valid one",
    (
        "/v1/admin/auth/mfa/verify",
        "POST",
    ): "second factor of a login in progress; the partial session is the credential",
    (
        "/v1/admin/auth/mfa/enrollment",
        "POST",
    ): "the single-use preauth challenge in the body is the credential; the "
    "service consumes it bound to purpose and network prefix and rejects if absent",
    ("/v1/account-requests/", "POST"): "public sign-up: anyone may ask for an account",
    ("/v1/account-requests/activate", "POST"): "the activation code is the credential",
    (
        "/v1/nodes/enroll",
        "POST",
    ): "a VPS being enrolled holds an enrollment token and nothing else, so "
    "requiring a session would make enrolment impossible; the token in the body "
    "is the credential, it is single-use, short-lived and revocable, and every "
    "refusal is indistinguishable so the route cannot be used as an oracle",
}


def _api_routes(routes: Iterable[BaseRoute]) -> Iterator[APIRoute]:
    """FastAPI keeps an included router nested under a _IncludedRouter rather
    than flattening its routes into app.routes, so a non-recursive walk sees
    only the two probe endpoints and passes trivially."""

    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif isinstance(route, _IncludedRouter):
            yield from _api_routes(route.original_router.routes)
        elif hasattr(route, "routes"):
            yield from _api_routes(route.routes)


def _routes() -> Iterator[tuple[str, str, Callable[..., object]]]:
    application = create_app(Settings(env="test"))
    for route in _api_routes(application.routes):
        for method in sorted((route.methods or set()) - {"HEAD", "OPTIONS"}):
            yield route.path, method, route.endpoint


def _referenced(function: Callable[..., object]) -> tuple[set[str], set[str]]:
    """(every identifier, every attribute actually called) in a function.

    Both halves are needed. Plain identifiers catch the two shared styles --
    `await require_admin_session(request)` in the body, and
    `Depends(require_user_session)` in the signature, where the helper is an
    argument rather than the callee. Attribute *calls* catch the auth module's
    own routes, which reach the service primitive directly; matching those on
    the call and not on any mention of the name keeps a local variable called
    `principal` from passing a route that does nothing.
    """

    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    return names, attributes


def _authorizes(function: Callable[..., object]) -> bool:
    """Whether the handler authorizes, directly or through one local helper.

    One level of indirection is deliberate and no more. Routes legitimately
    delegate to a module-local gate (accounts' `_authorize_reviewer`, the auth
    module's `_protect_mutation`), and refusing to follow that would force
    those onto the public list, which is the opposite of what this protects.
    Following arbitrarily deep would instead let a chain of calls that reaches
    an authorization helper by accident count as a gate.
    """

    names, attributes = _referenced(function)
    if (names & AUTHORIZATION_CALLS) or (attributes & AUTHORIZATION_PRIMITIVES):
        return True

    module = inspect.getmodule(function)
    for name in names:
        helper = getattr(module, name, None)
        if not inspect.isfunction(helper):
            continue
        helper_names, helper_attributes = _referenced(helper)
        if (helper_names & AUTHORIZATION_CALLS) or (helper_attributes & AUTHORIZATION_PRIMITIVES):
            return True
    return False


def test_every_route_authorizes_or_is_explicitly_public() -> None:
    unprotected: list[str] = []
    for path, method, endpoint in _routes():
        if (path, method) in PUBLIC_ROUTES:
            continue
        if _authorizes(endpoint):
            continue
        unprotected.append(f"{method} {path} ({getattr(endpoint, '__name__', endpoint)})")

    assert not unprotected, (
        "These routes neither authorize nor appear in PUBLIC_ROUTES. Add an "
        "authorization call, or add the route to PUBLIC_ROUTES with the reason "
        "it is safe to expose:\n  " + "\n  ".join(sorted(unprotected))
    )


def test_the_public_list_has_no_stale_entries() -> None:
    """A route that was public and has since been removed or protected leaves
    an entry behind that silently exempts whatever later takes its path."""

    registered = {(path, method) for path, method, _ in _routes()}
    stale = sorted(
        f"{method} {path}" for path, method in PUBLIC_ROUTES if (path, method) not in registered
    )

    assert not stale, "PUBLIC_ROUTES names routes that no longer exist:\n  " + "\n  ".join(stale)
