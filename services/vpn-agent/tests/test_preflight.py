"""The preflight check must actually detect a dead endpoint.

A reachability check that cannot fail is worse than none: it reports healthy
for the exact fault it exists to catch. These pin both directions against a
real socket rather than a mocked one, since what is being tested is whether
connecting works.
"""

import asyncio
import socket
from pathlib import PurePosixPath

import pytest

from nebula_agent import preflight
from nebula_agent.drivers.xray import NativeXrayDriver
from nebula_agent.drivers.xray_config_store import XrayConfigStore, XrayInboundProfile
from nebula_agent.preflight import EndpointCheck, _probe, check_advertised_endpoints
from nebula_agent.settings import Settings


def _store() -> XrayConfigStore:
    return XrayConfigStore(PurePosixPath("/var/lib/nebula/xray"), PurePosixPath("/etc/nebula/xray"))


def _free_port() -> int:
    """A port nothing is listening on: bind one, read it back, release it."""

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_probe_reports_a_listening_port_as_reachable() -> None:
    async def scenario() -> tuple[bool, str]:
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        try:
            return await _probe("127.0.0.1", port)
        finally:
            server.close()
            await server.wait_closed()

    reachable, detail = asyncio.run(scenario())
    assert reachable is True
    assert detail


def test_probe_reports_a_dead_port_as_unreachable() -> None:
    reachable, detail = asyncio.run(_probe("127.0.0.1", _free_port()))
    assert reachable is False
    assert detail


def test_a_fronted_profile_is_checked_on_the_public_port_not_the_inbound_one() -> None:
    """The XHTTP fault in one assertion: the inbound binds loopback:8446 with
    TLS terminated in front, and the client dials the public port. A check
    that probed the inbound's own port would connect happily to a port no
    client can reach, and call the broken configuration healthy."""

    settings = Settings(env="test", xray_public_port=8445, xray_local_listen_port=8446)
    fronted = XrayInboundProfile(
        protocol_profile_code="vless-xhttp-tls",
        transport="xhttp",
        listen="127.0.0.1",
        port=8446,
        security="none",
        xhttp_path="/xhttp",
    )
    driver = NativeXrayDriver(settings, _store(), profiles=(fronted,))

    endpoints = driver.advertised_endpoints()

    assert endpoints == (("vless-xhttp-tls", settings.xray_public_host, 8445, "xhttp"),), (
        "must report what the client dials, not what the inbound binds"
    )


def test_advertised_endpoints_covers_every_profile() -> None:
    """A profile missing from this list is never checked, which is the same
    silence the check exists to remove."""

    settings = Settings(env="test")
    profiles = (
        XrayInboundProfile(
            protocol_profile_code="vless-grpc-tls",
            transport="grpc",
            listen="0.0.0.0",  # noqa: S104 - deliberately public in this fixture
            port=8447,
            security="tls",
            grpc_service_name="grpc",
        ),
        XrayInboundProfile(
            protocol_profile_code="vless-ws-tls",
            transport="websocket",
            listen="0.0.0.0",  # noqa: S104 - deliberately public in this fixture
            port=8448,
            security="tls",
            ws_path="/ws",
        ),
    )
    driver = NativeXrayDriver(settings, _store(), profiles=profiles)

    codes = [code for code, _, _, _ in driver.advertised_endpoints()]

    assert codes == ["vless-grpc-tls", "vless-ws-tls"]


@pytest.mark.parametrize("reachable", [True, False, None])
def test_status_names_the_three_outcomes(reachable: bool | None) -> None:
    check = EndpointCheck("code", "host", 1, "grpc", reachable, "detail")
    assert check.status in {"OK", "FAIL", "SKIP"}


def test_a_dead_advertised_endpoint_is_reported_as_failed() -> None:
    """End to end through the real check: a profile advertising a port nothing
    listens on must come back FAIL, not OK."""

    port = _free_port()
    settings = Settings(env="test", xray_public_host="127.0.0.1")
    dead = XrayInboundProfile(
        protocol_profile_code="vless-grpc-tls",
        transport="grpc",
        listen="127.0.0.1",
        port=port,
        security="tls",
        grpc_service_name="grpc",
    )
    driver = NativeXrayDriver(settings, _store(), profiles=(dead,))

    results = asyncio.run(check_advertised_endpoints(settings, driver))

    assert [result.status for result in results] == ["FAIL"]
    assert results[0].port == port


def test_one_lost_connection_is_retried_before_failing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A single dropped connection is not a dead endpoint; two in a row are."""

    answers = iter([(False, "no answer within 5s"), (True, "accepted a connection")])
    calls = []

    async def flaky(host: str, port: int) -> tuple[bool, str]:
        calls.append(port)
        return next(answers)

    monkeypatch.setattr(preflight, "_probe", flaky)
    settings = Settings(env="test", xray_public_host="127.0.0.1")
    profile = XrayInboundProfile(
        protocol_profile_code="vless-grpc-tls",
        transport="grpc",
        listen="127.0.0.1",
        port=8447,
        security="tls",
        grpc_service_name="grpc",
    )
    driver = NativeXrayDriver(settings, _store(), profiles=(profile,))

    results = asyncio.run(check_advertised_endpoints(settings, driver))

    assert [result.status for result in results] == ["OK"]
    assert len(calls) == 2


def test_a_live_advertised_endpoint_is_reported_as_ok() -> None:
    """The other direction, so a check that always fails cannot pass either."""

    async def scenario() -> tuple[EndpointCheck, ...]:
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        settings = Settings(env="test", xray_public_host="127.0.0.1")
        live = XrayInboundProfile(
            protocol_profile_code="vless-grpc-tls",
            transport="grpc",
            listen="127.0.0.1",
            port=port,
            security="tls",
            grpc_service_name="grpc",
        )
        driver = NativeXrayDriver(settings, _store(), profiles=(live,))
        try:
            return await check_advertised_endpoints(settings, driver)
        finally:
            server.close()
            await server.wait_closed()

    assert [result.status for result in asyncio.run(scenario())] == ["OK"]


def test_the_fake_driver_is_refused_rather_than_reported_healthy() -> None:
    """A host configured with the fake driver serves no real traffic. Saying
    so is the useful answer; checking its made-up endpoints and printing OK
    would be exactly the false assurance this exists to prevent."""

    with pytest.raises(SystemExit, match="does not serve real endpoints"):
        asyncio.run(check_advertised_endpoints(Settings(env="test")))


# --- crash-loop detection ---------------------------------------------------
#
# A bad config restarted Hysteria2 25,126 times with nothing reporting it. This
# is the check that would have said so, and it is worth testing precisely,
# because both of its wrong answers are bad: missing a real loop restores the
# original silence, and calling a healthy server a loop would send someone
# chasing an outage that is not happening.


class _FakeProcess:
    def __init__(self, stdout: bytes, returncode: int) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""


def _fake_systemctl(
    monkeypatch: pytest.MonkeyPatch, values: list[bytes], returncode: int = 0
) -> None:
    async def _exec(*_args: object, **_kwargs: object) -> _FakeProcess:
        return _FakeProcess(values.pop(0) if values else b"0", returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _exec)


def test_restart_count_reads_the_number_systemctl_prints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_systemctl(monkeypatch, [b"7\n"])
    assert asyncio.run(preflight._restart_count("nebula-xray")) == 7


def test_restart_count_is_none_when_systemctl_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host without systemd must report unknown, not zero. Zero would read as
    'stable' and quietly assert something this check cannot see."""

    _fake_systemctl(monkeypatch, [b""], returncode=1)
    assert asyncio.run(preflight._restart_count("nebula-xray")) is None


def test_restart_count_is_none_when_the_output_is_not_a_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_systemctl(monkeypatch, [b"not-a-number"])
    assert asyncio.run(preflight._restart_count("nebula-xray")) is None


def _no_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight, "_LOOP_SAMPLE_SECONDS", 0.0)


def test_a_counter_that_moves_during_the_check_is_a_crash_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_wait(monkeypatch)
    # Keyed by unit rather than a flat sequence: both units are sampled before
    # the wait and both again after, so a positional fake encodes the sampling
    # order and breaks whenever that changes.
    readings = {"nebula-xray": [3, 9], "nebula-hysteria": [0, 0]}

    async def _count(unit: str) -> int:
        return readings[unit].pop(0)

    monkeypatch.setattr(preflight, "_restart_count", _count)
    results = {
        u: (ok, detail)
        for u, ok, detail in asyncio.run(preflight.check_units_are_not_crash_looping())
    }

    healthy, detail = results["nebula-xray"]
    assert healthy is False
    assert "6x" in detail, detail
    assert results["nebula-hysteria"][0] is True


def test_a_still_counter_is_stable_even_when_it_is_large(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restarts are also how config is applied, so a high total is normal. Only
    movement during the check means anything."""

    _no_wait(monkeypatch)

    async def _count(_unit: str) -> int:
        return 512

    monkeypatch.setattr(preflight, "_restart_count", _count)
    results = asyncio.run(preflight.check_units_are_not_crash_looping())

    assert [ok for _, ok, _ in results] == [True, True]


def test_an_unavailable_counter_is_reported_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_wait(monkeypatch)

    async def _count(_unit: str) -> None:
        return None

    monkeypatch.setattr(preflight, "_restart_count", _count)
    results = asyncio.run(preflight.check_units_are_not_crash_looping())

    assert [ok for _, ok, _ in results] == [None, None]


# --- the command itself -----------------------------------------------------


def _stub_checks(
    monkeypatch: pytest.MonkeyPatch,
    endpoints: tuple[EndpointCheck, ...],
    units: tuple[tuple[str, bool | None, str], ...],
) -> None:
    async def _endpoints(*_a: object, **_k: object) -> tuple[EndpointCheck, ...]:
        return endpoints

    async def _units() -> tuple[tuple[str, bool | None, str], ...]:
        return units

    monkeypatch.setattr(preflight, "check_advertised_endpoints", _endpoints)
    monkeypatch.setattr(preflight, "check_units_are_not_crash_looping", _units)
    monkeypatch.setattr(preflight, "get_settings", lambda: Settings(env="test"))


def test_the_command_exits_zero_when_everything_answers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_checks(
        monkeypatch,
        (EndpointCheck("vless-grpc-tls", "host", 8447, "grpc", True, "ok"),),
        (("nebula-xray", True, "stable"),),
    )
    preflight.main()
    assert "no unit is crash looping" in capsys.readouterr().out


def test_a_dead_endpoint_fails_the_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_checks(
        monkeypatch,
        (EndpointCheck("vless-grpc-tls", "host", 8447, "grpc", False, "no answer"),),
        (("nebula-xray", True, "stable"),),
    )
    with pytest.raises(SystemExit) as exit_info:
        preflight.main()
    assert exit_info.value.code == 1
    assert "did not answer" in capsys.readouterr().err


def test_a_crash_looping_unit_fails_the_command_even_if_every_endpoint_answers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The two checks are independent: a server can serve every port while a
    transport restarts on a loop behind it."""

    _stub_checks(
        monkeypatch,
        (EndpointCheck("vless-grpc-tls", "host", 8447, "grpc", True, "ok"),),
        (("nebula-hysteria", False, "restarted 6x"),),
    )
    with pytest.raises(SystemExit) as exit_info:
        preflight.main()
    assert exit_info.value.code == 1
    assert "restarting on a loop" in capsys.readouterr().err


def test_a_skipped_endpoint_does_not_fail_the_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Hysteria2 is always SKIP. If that counted as a failure the command would
    be red on every healthy server and would stop being run."""

    _stub_checks(
        monkeypatch,
        (EndpointCheck("hysteria2", "host", 8450, "hysteria", None, "UDP"),),
        (("nebula-xray", True, "stable"),),
    )
    preflight.main()
    out = capsys.readouterr().out
    assert "SKIP" in out
    assert "no unit is crash looping" in out
