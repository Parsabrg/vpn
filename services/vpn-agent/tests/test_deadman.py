"""The one check whose alert is produced by silence.

Everything else here reports *from* the VPS, so none of it can report the VPS
being gone: power loss, a network partition, a kernel panic, an unpaid invoice.
In every one of those the alerter dies with the thing it was watching, and the
result is silence indistinguishable from health.

So the properties worth pinning are mostly about what this must *not* do. It
must not raise, must not delay, and must not be skipped on the runs where
something is actually wrong -- because those are exactly the runs where the
email path is most likely to be the broken thing.
"""

import urllib.error

import pytest

from nebula_agent.alerting import ping_dead_man_switch

_URLOPEN = "nebula_agent.alerting.urllib.request.urlopen"
URL = "https://hc.example.org/abc123"


class _Response:
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _record(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        seen.append(request.full_url)  # type: ignore[attr-defined]
        return _Response()

    monkeypatch.setattr(_URLOPEN, _urlopen)
    return seen


def test_a_healthy_run_pings_the_plain_url(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _record(monkeypatch)

    ping_dead_man_switch(URL, healthy=True)

    assert seen == [URL]


def test_an_unhealthy_run_pings_the_failure_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Duplication with the email on purpose. The case worth covering is Resend
    being down or the mail landing in spam -- exactly when the primary path is
    the thing that is broken."""

    seen = _record(monkeypatch)

    ping_dead_man_switch(URL, healthy=False)

    assert seen == [f"{URL}/fail"]


def test_a_trailing_slash_does_not_produce_a_double_slash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Copying the URL out of a dashboard is how it will be configured, and
    some of them include the slash. //fail is a 404 at most providers, which
    would silently mean the failure ping never registered."""

    seen = _record(monkeypatch)

    ping_dead_man_switch(f"{URL}/", healthy=False)

    assert seen == [f"{URL}/fail"]


def test_an_unreachable_service_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """The caller is a health check in the middle of reporting real problems.
    Failing it over an unreachable monitoring service would suppress the alert
    that mattered."""

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(_URLOPEN, _urlopen)

    ping_dead_man_switch(URL, healthy=True)


def test_a_timeout_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    def _urlopen(request: object, timeout: float = 0) -> _Response:
        raise TimeoutError

    monkeypatch.setattr(_URLOPEN, _urlopen)

    ping_dead_man_switch(URL, healthy=True)


def test_a_non_http_url_is_refused_rather_than_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file: or custom scheme would be a misconfiguration that silently
    stopped pinging, and a switch that is not pinging looks identical to a
    dead host."""

    seen = _record(monkeypatch)

    ping_dead_man_switch("file:///etc/passwd", healthy=True)

    assert seen == []


def test_the_request_carries_an_identifying_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers: dict[str, str] = {}

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        headers.update(request.headers)  # type: ignore[attr-defined]
        return _Response()

    monkeypatch.setattr(_URLOPEN, _urlopen)
    ping_dead_man_switch(URL, healthy=True)

    assert headers.get("User-agent", "").startswith("nebula-agent/")


def test_the_ping_carries_no_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """A liveness ping should say only that this host is alive. Anything else
    is deployment detail handed to a third party for no reason."""

    bodies: list[object] = []

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        bodies.append(request.data)  # type: ignore[attr-defined]
        return _Response()

    monkeypatch.setattr(_URLOPEN, _urlopen)
    ping_dead_man_switch(URL, healthy=True)

    assert bodies == [None]
