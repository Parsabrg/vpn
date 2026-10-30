"""Blocked from Iran, versus broken everywhere, versus not knowing.

Three states, and conflating any two of them makes this check worse than not
having it. The first version conflated the first two: it sent an HTTPS request
to a VLESS inbound, which the server correctly refuses, and read that refusal
as censorship. It reported every transport permanently blocked. A control run
from Germany returned the identical result, which is what caught it.

So the discrimination is the thing under test here, not the plumbing.
"""

import json
import urllib.error
from pathlib import Path, PurePosixPath
from typing import ClassVar, cast

import pytest

from nebula_agent import reachability
from nebula_agent.reachability import (
    PortReachability,
    ProbeUnavailable,
    check_reachable_from_iran,
    count_reached,
    resolve,
)
from nebula_agent.settings import Settings

_URLOPEN = "nebula_agent.reachability.urllib.request.urlopen"
SERVER = "203.0.113.10"


def _measurement(*last_hops: str | None) -> dict[str, object]:
    return {
        "status": "finished",
        "results": [
            {"result": {"hops": [{"resolvedAddress": hop}] if hop else []}} for hop in last_hops
        ],
    }


# --- reading a traceroute ---------------------------------------------------


def test_a_traceroute_ending_at_the_server_counts_as_reached() -> None:
    assert count_reached(_measurement(SERVER, SERVER), SERVER) == (2, 2)


def test_a_traceroute_stopping_short_does_not_count() -> None:
    """A traceroute that ends somewhere else ended at whatever dropped it,
    which for a blocked destination is the border rather than the host."""

    assert count_reached(_measurement(SERVER, "10.0.0.1", None), SERVER) == (1, 3)


def test_a_malformed_measurement_reads_as_nothing_reached() -> None:
    assert count_reached({"results": "not a list"}, SERVER) == (0, 0)
    assert count_reached({}, SERVER) == (0, 0)


# --- the three states -------------------------------------------------------


def _result(iran: tuple[int, int], control: tuple[int, int]) -> PortReachability:
    return PortReachability(
        protocol_profile_code="vless-grpc-tls",
        port=8447,
        iran_reached=iran[0],
        iran_total=iran[1],
        control_reached=control[0],
        control_total=control[1],
    )


def test_unreachable_from_iran_but_reachable_elsewhere_is_blocking() -> None:
    assert _result(iran=(0, 5), control=(3, 4)).blocked_from_iran is True


def test_unreachable_from_everywhere_is_a_server_fault_not_blocking() -> None:
    """The trap this check exists to avoid. The other checks already report a
    server that answers nowhere; repeating it here as censorship would send
    someone hunting a censor for an outage of their own making."""

    assert _result(iran=(0, 5), control=(0, 4)).blocked_from_iran is False


def test_reachable_from_iran_is_not_blocking() -> None:
    assert _result(iran=(5, 5), control=(3, 4)).blocked_from_iran is False


def test_partial_reachability_from_iran_is_not_reported_as_blocked() -> None:
    """One Iranian network filtering while three others do not is real and
    worth seeing in the summary, but it is not the total block that warrants
    telling users to switch transport."""

    assert _result(iran=(1, 5), control=(3, 4)).blocked_from_iran is False


def test_no_iranian_probes_at_all_is_not_reported_as_blocked() -> None:
    """Globalping having no Iran probes available is not knowing, and must not
    become a censorship alert."""

    assert _result(iran=(0, 0), control=(4, 4)).blocked_from_iran is False


def test_a_noisy_control_still_permits_a_blocking_verdict() -> None:
    """Measured against the real service: control probes complete TCP
    traceroute less reliably than the Iranian ones did (2/4 vs 5/5). Requiring
    every control probe to succeed would have suppressed real findings."""

    assert _result(iran=(0, 5), control=(1, 4)).blocked_from_iran is True


def test_the_summary_states_both_sides() -> None:
    """A reader has to be able to tell blocking from an outage at a glance, so
    the control result belongs in the line, not just in the verdict."""

    summary = _result(iran=(0, 5), control=(3, 4)).summary

    assert "0/5 Iran" in summary
    assert "3/4 elsewhere" in summary


# --- the measurement loop ---------------------------------------------------


class _Response:
    def __init__(self, payload: object) -> None:
        self._payload = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_udp_transports_are_skipped_rather_than_guessed_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hysteria2 is QUIC over UDP. A TCP traceroute to that port measures
    nothing about it, and reporting it blocked on that basis would be a
    fabricated result rather than a missing one."""

    calls: list[object] = []

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        calls.append(request)
        return _Response({"id": "m1", "status": "finished", "results": []})

    monkeypatch.setattr(_URLOPEN, _urlopen)

    results = check_reachable_from_iran(
        [("hysteria2", "h", 8450, "hysteria")], SERVER, sleep=lambda _s: None
    )

    assert results == []
    assert calls == [], "no measurement should be dispatched for a UDP transport"


def test_each_tcp_endpoint_is_measured_from_iran_and_a_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posted: list[dict[str, object]] = []

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        data = getattr(request, "data", None)
        if data:
            posted.append(json.loads(data))
            return _Response({"id": f"m{len(posted)}"})
        return _Response(_measurement(SERVER))

    monkeypatch.setattr(_URLOPEN, _urlopen)

    check_reachable_from_iran(
        [("vless-grpc-tls", "h", 8447, "grpc")], SERVER, sleep=lambda _s: None
    )

    assert len(posted) == 2, "one measurement from Iran, one control"
    countries = [
        loc["country"] for body in posted for loc in cast(list[dict[str, str]], body["locations"])
    ]
    assert "IR" in countries
    assert {"DE", "NL", "US", "GB"} & set(countries), "a control outside Iran is required"
    protocols = [cast(dict[str, str], body["measurementOptions"])["protocol"] for body in posted]
    assert protocols == ["TCP", "TCP"]


def test_a_measurement_service_outage_raises_rather_than_reporting_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not knowing and being blocked are different states. Reporting the first
    as the second would raise a censorship alarm every time an unrelated third
    party had an outage."""

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        raise urllib.error.URLError("globalping is down")

    monkeypatch.setattr(_URLOPEN, _urlopen)

    with pytest.raises(ProbeUnavailable):
        check_reachable_from_iran(
            [("vless-grpc-tls", "h", 8447, "grpc")], SERVER, sleep=lambda _s: None
        )


def test_a_measurement_that_never_finishes_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _urlopen(request: object, timeout: float = 0) -> _Response:
        if getattr(request, "data", None):
            return _Response({"id": "m1"})
        return _Response({"status": "in-progress", "results": []})

    monkeypatch.setattr(_URLOPEN, _urlopen)

    with pytest.raises(ProbeUnavailable, match="did not finish"):
        check_reachable_from_iran(
            [("vless-grpc-tls", "h", 8447, "grpc")], SERVER, sleep=lambda _s: None
        )


def test_a_response_without_an_id_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_URLOPEN, lambda *_a, **_k: _Response({"error": "rate limited"}))

    with pytest.raises(ProbeUnavailable, match="no id"):
        check_reachable_from_iran(
            [("vless-grpc-tls", "h", 8447, "grpc")], SERVER, sleep=lambda _s: None
        )


def test_an_unresolvable_host_returns_none_rather_than_raising() -> None:
    assert resolve("this-host-does-not-exist.invalid") is None


# --- the command ------------------------------------------------------------


class _Mailer:
    sent: ClassVar[dict[str, str]] = {}

    @classmethod
    def from_files(cls, *_args: object) -> "_Mailer":
        return cls()

    def send(self, *, subject: str, body: str) -> str:
        _Mailer.sent = {"subject": subject, "body": body}
        return "msg_1"


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "reachability_state_file": PurePosixPath(str(tmp_path / "state")),
        "xray_public_host": "example.org",
    }
    base.update(overrides)
    return Settings(env="test").model_copy(update=base)


def _configured(tmp_path: Path) -> Settings:
    key = tmp_path / "key"
    key.write_text("re_key")
    return _settings(
        tmp_path,
        alert_recipient="me@example.org",
        alert_sender="Nebula VPN <alerts@example.org>",
        alert_api_key_file=PurePosixPath(str(key)),
    )


class _Driver:
    def advertised_endpoints(self) -> tuple[tuple[str, str, int, str], ...]:
        return (("vless-grpc-tls", "example.org", 8447, "grpc"),)


def _wire(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, results: list[PortReachability]
) -> None:
    monkeypatch.setattr(reachability, "get_settings", lambda: settings)
    monkeypatch.setattr(reachability, "build_xray_driver", lambda _s: _Driver())
    monkeypatch.setattr(reachability, "resolve", lambda _h: SERVER)
    monkeypatch.setattr(reachability, "check_reachable_from_iran", lambda *_a, **_k: results)
    monkeypatch.setattr(reachability, "Mailer", _Mailer)
    _Mailer.sent = {}


def test_the_command_reports_reachable_transports_without_alerting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _wire(monkeypatch, _configured(tmp_path), [_result(iran=(5, 5), control=(3, 4))])

    reachability.main()

    assert "ok" in capsys.readouterr().out
    assert _Mailer.sent == {}


def test_a_blocked_transport_alerts_and_says_what_to_do(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An alert saying only "blocked" leaves the reader to work out that the
    fix is steering users to another transport."""

    _wire(monkeypatch, _configured(tmp_path), [_result(iran=(0, 5), control=(3, 4))])

    reachability.main()

    assert "blocked from Iran" in _Mailer.sent["subject"]
    assert "steer them to" in _Mailer.sent["body"]


def test_the_alert_is_not_repeated_every_hour(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Blocking persists for days. Re-sending hourly would bury the transport
    that got blocked next."""

    _wire(monkeypatch, _configured(tmp_path), [_result(iran=(0, 5), control=(3, 4))])
    reachability.main()
    _Mailer.sent = {}

    reachability.main()

    assert _Mailer.sent == {}


def test_an_endpoint_unreachable_everywhere_does_not_alert_as_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end through the command: a server that answers nowhere is the
    health check's business, not a censorship report."""

    _wire(monkeypatch, _configured(tmp_path), [_result(iran=(0, 5), control=(0, 4))])

    reachability.main()

    assert _Mailer.sent == {}
    assert "BLOCKED" not in capsys.readouterr().out


def test_a_measurement_outage_fails_the_command_without_alerting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _configured(tmp_path)
    monkeypatch.setattr(reachability, "get_settings", lambda: settings)
    monkeypatch.setattr(reachability, "build_xray_driver", lambda _s: _Driver())
    monkeypatch.setattr(reachability, "resolve", lambda _h: SERVER)
    monkeypatch.setattr(reachability, "Mailer", _Mailer)
    _Mailer.sent = {}

    def _boom(*_a: object, **_k: object) -> list[PortReachability]:
        raise ProbeUnavailable("globalping is down")

    monkeypatch.setattr(reachability, "check_reachable_from_iran", _boom)

    with pytest.raises(SystemExit, match="could not measure from Iran"):
        reachability.main()
    assert _Mailer.sent == {}, "an unusable probe service must never send a censorship alert"


def test_an_unresolvable_public_host_fails_the_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _configured(tmp_path)
    monkeypatch.setattr(reachability, "get_settings", lambda: settings)
    monkeypatch.setattr(reachability, "build_xray_driver", lambda _s: _Driver())
    monkeypatch.setattr(reachability, "resolve", lambda _h: None)

    with pytest.raises(SystemExit, match="could not resolve"):
        reachability.main()


def test_the_fake_driver_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _configured(tmp_path)
    monkeypatch.setattr(reachability, "get_settings", lambda: settings)
    monkeypatch.setattr(reachability, "build_xray_driver", lambda _s: object())

    with pytest.raises(SystemExit, match="serves no real endpoints"):
        reachability.main()


def test_a_blocked_transport_with_no_recipient_fails_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire(monkeypatch, _settings(tmp_path), [_result(iran=(0, 5), control=(3, 4))])

    with pytest.raises(SystemExit, match="no alert recipient"):
        reachability.main()
