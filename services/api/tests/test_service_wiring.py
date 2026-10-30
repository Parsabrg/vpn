"""Every service the app hands to a route is actually built.

`create_app` declares each service as `None`, builds it further down, and
attaches it to `app.state` at the end. Miss the middle step and nothing
complains: the module imports, the router registers, the app starts, and
every test that injects its own fake keeps passing -- while the route answers
503 forever.

That is exactly what happened to node enrolment. It shipped, deployed, and
returned "temporarily unavailable" to the first real client, because
`effective_enrollment_service` was declared and attached but never
constructed. Its route tests passed throughout: they put a fake on
`app.state` themselves, so they never touched the wiring they relied on.

Read as source rather than by starting the app, deliberately. Building the
real thing needs a database, a Redis and the key material, and a guard that
needs all three is one that gets skipped in exactly the environment that
would have caught this.
"""

import re
from pathlib import Path

MAIN = Path(__file__).resolve().parents[1] / "src" / "nebula_api" / "main.py"

# Matches `    effective_usage_service: UsageService | None = None`
_DECLARATION = re.compile(
    r"^\s*(effective_\w+)\s*:\s*[\w\[\], |]+?\s*\|\s*None\s*=\s*None\s*$",
    re.MULTILINE,
)


def _source() -> str:
    return MAIN.read_text(encoding="utf-8")


def _declared_services(source: str) -> list[str]:
    names = _DECLARATION.findall(source)
    # An empty result means the pattern has drifted and this file is
    # measuring nothing, which is worse than failing.
    assert names, "no optional services found; this guard has stopped working"
    return names


def _is_constructed(source: str, name: str) -> bool:
    """Whether anything assigns `name` something other than None."""

    for line in source.splitlines():
        stripped = line.strip()
        if not stripped.startswith(f"{name} = "):
            continue
        if stripped != f"{name} = None":
            return True
    return False


def _is_attached(source: str, name: str) -> bool:
    """Whether `name` is put on app.state."""

    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("application.state.") and stripped.endswith(f"= {name}"):
            return True
    return False


def test_every_declared_service_is_constructed() -> None:
    source = _source()

    unbuilt = [name for name in _declared_services(source) if not _is_constructed(source, name)]

    assert not unbuilt, (
        "declared, attached to app.state, and never built: "
        + ", ".join(unbuilt)
        + ". The route answers 503 in production while every test that "
        "injects its own fake keeps passing."
    )


def test_every_declared_service_is_attached() -> None:
    # The other half, and the same failure wearing a different hat: a service
    # built and then left behind is one the route still cannot find.
    source = _source()

    unattached = [name for name in _declared_services(source) if not _is_attached(source, name)]

    assert not unattached, "built but never attached: " + ", ".join(unattached)


def test_node_enrolment_in_particular_is_wired() -> None:
    # Named outright because this is the one that reached production unbuilt.
    # A general guard that quietly stopped covering it would look identical
    # to one that still did.
    source = _source()

    assert _is_constructed(source, "effective_enrollment_service"), (
        "node enrolment answers 503 for every client when this is not built"
    )
    assert _is_attached(source, "effective_enrollment_service")
