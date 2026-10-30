"""The layer that shells out, and the aggregator that decides what is reported.

Kept apart from the other two health check test files because everything here
is about the boundary with the operating system: a missing binary, a
non-zero exit, a host that is not running systemd at all. Those are the paths
where a check most easily starts silently answering "fine" to every question.
"""

import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from nebula_agent import healthcheck
from nebula_agent.healthcheck import Problem
from nebula_agent.preflight import EndpointCheck
from nebula_agent.settings import Settings

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


class _Completed:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# --- shelling out -----------------------------------------------------------


def test_run_returns_none_when_the_binary_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """None means "could not ask", and every caller turns that into a reported
    problem rather than a pass. A host missing journalctl should say so."""

    def _boom(*_a: object, **_k: object) -> None:
        raise FileNotFoundError("no such binary")

    monkeypatch.setattr("nebula_agent.healthcheck.subprocess.run", _boom)

    assert healthcheck._run(["/usr/bin/anything"]) is None


def test_run_returns_none_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _hang(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired(cmd="x", timeout=15)

    monkeypatch.setattr("nebula_agent.healthcheck.subprocess.run", _hang)

    assert healthcheck._run(["/usr/bin/anything"]) is None


def test_systemctl_returns_none_on_a_non_zero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """`is-active` exits non-zero for an inactive unit, and `show` does for a
    unit that does not exist. Neither may be read as an answer."""

    monkeypatch.setattr(healthcheck, "_run", lambda _argv: _Completed("inactive", returncode=3))

    assert healthcheck._systemctl("is-active", "nebula-xray") is None


def test_systemctl_strips_its_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(healthcheck, "_run", lambda _argv: _Completed("active\n"))

    assert healthcheck._systemctl("is-active", "nebula-xray") == "active"


def test_the_journal_tail_says_so_when_it_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(healthcheck, "_run", lambda _argv: None)

    assert healthcheck._journal_tail("nebula-xray") == "(journal unavailable)"


def test_an_empty_journal_is_labelled_rather_than_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An alert whose body is empty reads as a broken alerter."""

    monkeypatch.setattr(healthcheck, "_run", lambda _argv: _Completed("   \n"))

    assert healthcheck._journal_tail("nebula-xray") == "(no journal output)"


def test_the_journal_tail_asks_for_the_named_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, list[str]] = {}

    def _capture(argv: list[str]) -> _Completed:
        seen["argv"] = argv
        return _Completed("lines")

    monkeypatch.setattr(healthcheck, "_run", _capture)
    healthcheck._journal_tail("nebula-hysteria", lines=5)

    assert seen["argv"][:5] == ["/usr/bin/journalctl", "-u", "nebula-hysteria", "-n", "5"]


# --- what gets aggregated ---------------------------------------------------


def _stub_all(
    monkeypatch: pytest.MonkeyPatch,
    *,
    timers: list[Problem] | None = None,
    units: list[Problem] | None = None,
    certs: list[Problem] | None = None,
    containers: list[Problem] | None = None,
    loops: tuple[tuple[str, bool | None, str], ...] = (),
    endpoints: tuple[EndpointCheck, ...] = (),
) -> None:
    monkeypatch.setattr(healthcheck, "check_timers_are_still_firing", lambda _now: timers or [])
    monkeypatch.setattr(healthcheck, "check_units_are_active", lambda: units or [])
    monkeypatch.setattr(healthcheck, "check_certificates", lambda _s, _now: certs or [])
    monkeypatch.setattr(healthcheck, "check_containers_are_healthy", lambda: containers or [])

    async def _loops() -> tuple[tuple[str, bool | None, str], ...]:
        return loops

    async def _endpoints(*_a: object, **_k: object) -> tuple[EndpointCheck, ...]:
        return endpoints

    monkeypatch.setattr(healthcheck, "check_units_are_not_crash_looping", _loops)
    monkeypatch.setattr(healthcheck, "check_advertised_endpoints", _endpoints)


def _collect(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> list[Problem]:
    import asyncio

    _stub_all(monkeypatch, **kwargs)  # type: ignore[arg-type]
    return asyncio.run(healthcheck.collect_problems(Settings(env="test"), NOW))


def test_a_healthy_system_produces_no_problems(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _collect(monkeypatch) == []


def test_every_source_reaches_the_report(monkeypatch: pytest.MonkeyPatch) -> None:
    """A check whose result is collected but dropped is worse than one that was
    never written, because the gap is invisible."""

    problems = _collect(
        monkeypatch,
        timers=[Problem("timer stopped", "")],
        units=[Problem("unit down", "")],
        certs=[Problem("cert expiring", "")],
        containers=[Problem("usage container unhealthy", "")],
        loops=(("nebula-xray", False, "restarted 6x"),),
        endpoints=(EndpointCheck("vless-grpc-tls", "h", 8447, "grpc", False, "no answer"),),
    )

    subjects = [p.subject for p in problems]
    assert "timer stopped" in subjects
    assert "unit down" in subjects
    assert "cert expiring" in subjects
    assert "usage container unhealthy" in subjects
    assert "nebula-xray is crash looping" in subjects
    assert "vless-grpc-tls is advertised but does not answer" in subjects


def test_a_skipped_endpoint_is_not_a_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hysteria2 is always SKIP -- it is QUIC over UDP and connecting proves
    nothing. Counting that as a fault would alert on every healthy server, and
    the alerts would be muted within a week."""

    problems = _collect(
        monkeypatch,
        endpoints=(EndpointCheck("hysteria2", "h", 8450, "hysteria", None, "UDP"),),
    )

    assert problems == []


def test_a_healthy_unit_is_not_a_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    problems = _collect(monkeypatch, loops=(("nebula-xray", True, "stable"),))

    assert problems == []


def test_an_unknown_restart_count_is_not_treated_as_a_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """None means the counter could not be read, not that the unit is looping.
    Reporting it as a crash loop would be a false alarm on any host where
    systemctl is unavailable."""

    problems = _collect(monkeypatch, loops=(("nebula-xray", None, "unavailable"),))

    assert problems == []


def test_a_dead_endpoint_explains_what_a_user_would_see(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This is the XHTTP fault. The alert has to say what it means, because
    "endpoint unreachable" on a server where every process is up reads as a
    monitoring glitch rather than a transport that carries nothing."""

    problems = _collect(
        monkeypatch,
        endpoints=(
            EndpointCheck("vless-xhttp-tls", "api.example.org", 8445, "xhttp", False, "no answer"),
        ),
    )

    assert "api.example.org:8445" in problems[0].detail
    assert "pass no traffic" in problems[0].detail


def test_the_state_file_default_survives_a_reboot() -> None:
    """/run is tmpfs. Keeping the dedupe state there would re-send every
    standing problem on every boot."""

    state = Settings(env="test").alert_state_file

    assert not str(state).startswith("/run/")
    assert state == PurePosixPath("/var/lib/nebula/healthcheck.state")


def test_the_state_file_round_trips(tmp_path: Path) -> None:
    state = tmp_path / "state"
    healthcheck._write_state(state, "a\nb", NOW)

    fingerprint, sent_at = healthcheck._read_state(state)

    assert fingerprint == "a\nb"
    assert sent_at == NOW


def test_an_unreadable_state_file_reads_as_no_history(tmp_path: Path) -> None:
    fingerprint, sent_at = healthcheck._read_state(tmp_path / "absent")

    assert fingerprint == ""
    assert sent_at is None


def test_a_corrupt_state_file_reads_as_no_timestamp(tmp_path: Path) -> None:
    """A truncated write must not crash the check that is trying to report a
    real problem."""

    state = tmp_path / "state"
    state.write_text("not-a-timestamp\nxray down")

    fingerprint, sent_at = healthcheck._read_state(state)

    assert fingerprint == "xray down"
    assert sent_at is None
