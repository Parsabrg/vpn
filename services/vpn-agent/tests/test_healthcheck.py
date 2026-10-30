"""The checks that catch what no failure event would.

Every fault this deployment has had was found by a person noticing, so the
value of these is entirely in whether they fire when they should and stay
quiet when they should not. Both halves are tested: a check that never fires
restores the original silence, and one that fires constantly gets filtered
within a week, which is worse than nothing because it looks like monitoring.
"""

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

import pytest

from nebula_agent import healthcheck
from nebula_agent.healthcheck import Problem, check_timers_are_still_firing, compose, should_send
from nebula_agent.settings import Settings

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def _systemctl_returning(monkeypatch: pytest.MonkeyPatch, answers: dict[str, str | None]) -> None:
    def _fake(*args: str) -> str | None:
        # The timer name is the last argument of `show -p ... --value <timer>`
        # and the only argument of `is-active <unit>`.
        return answers.get(args[-1])

    monkeypatch.setattr(healthcheck, "_systemctl", _fake)


# --- the dead man's switch --------------------------------------------------
#
# This is the one that matters most. Revoking a device marks its credentials
# REVOKING and hands them to nebula-reconcile.timer to remove from the server.
# A timer that stops firing produces no event at all, so without this check a
# revoked device keeps working indefinitely while every screen says otherwise.


def test_a_recent_reconcile_trigger_is_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    recent = (NOW - timedelta(minutes=10)).strftime("%a %Y-%m-%d %H:%M:%S UTC")
    _systemctl_returning(
        monkeypatch,
        {
            "nebula-reconcile.timer": recent,
            "nebula-backup.timer": (NOW - timedelta(hours=2)).strftime("%a %Y-%m-%d %H:%M:%S UTC"),
        },
    )

    assert check_timers_are_still_firing(NOW) == []


def test_a_reconcile_timer_that_stopped_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    stale = (NOW - timedelta(hours=3)).strftime("%a %Y-%m-%d %H:%M:%S UTC")
    _systemctl_returning(
        monkeypatch,
        {
            "nebula-reconcile.timer": stale,
            "nebula-backup.timer": (NOW - timedelta(hours=2)).strftime("%a %Y-%m-%d %H:%M:%S UTC"),
        },
    )

    problems = check_timers_are_still_firing(NOW)

    assert [p.subject for p in problems] == ["nebula-reconcile.timer has not fired in 3:00:00"]


def test_the_backup_timer_gets_a_daily_allowance_not_the_reconcile_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three hours is stale for a 15-minute timer and perfectly normal for a
    daily one. Sharing a threshold would either page every morning or never
    notice reconciliation stopping."""

    three_hours_ago = (NOW - timedelta(hours=3)).strftime("%a %Y-%m-%d %H:%M:%S UTC")
    _systemctl_returning(
        monkeypatch,
        {
            "nebula-reconcile.timer": (NOW - timedelta(minutes=5)).strftime(
                "%a %Y-%m-%d %H:%M:%S UTC"
            ),
            "nebula-backup.timer": three_hours_ago,
        },
    )

    assert check_timers_are_still_firing(NOW) == []


def test_a_timer_that_never_fired_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    _systemctl_returning(
        monkeypatch, {"nebula-reconcile.timer": "n/a", "nebula-backup.timer": "n/a"}
    )

    subjects = [p.subject for p in check_timers_are_still_firing(NOW)]

    assert subjects == [
        "nebula-reconcile.timer has never fired",
        "nebula-backup.timer has never fired",
    ]


def test_an_unqueryable_timer_is_reported_rather_than_assumed_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown is not the same as fine. Treating a failed query as healthy is
    how a check quietly stops checking."""

    _systemctl_returning(monkeypatch, {})

    assert len(check_timers_are_still_firing(NOW)) == 2


# --- not sending the same mail every twenty minutes -------------------------


def test_a_new_problem_is_sent(tmp_path: Path) -> None:
    state = tmp_path / "state"
    assert should_send([Problem("xray down", "")], state, NOW) is True


def test_the_same_problem_is_not_sent_again_twenty_minutes_later(tmp_path: Path) -> None:
    state = tmp_path / "state"
    should_send([Problem("xray down", "")], state, NOW)

    assert should_send([Problem("xray down", "")], state, NOW + timedelta(minutes=20)) is False


def test_a_standing_problem_is_repeated_once_a_day(tmp_path: Path) -> None:
    """A fault reported once at 3am and never again is one nobody acts on."""

    state = tmp_path / "state"
    should_send([Problem("xray down", "")], state, NOW)

    assert should_send([Problem("xray down", "")], state, NOW + timedelta(days=1)) is True


def test_a_changed_problem_set_is_sent_immediately(tmp_path: Path) -> None:
    """Something new going wrong while something is already wrong must not be
    swallowed by the daily suppression."""

    state = tmp_path / "state"
    should_send([Problem("xray down", "")], state, NOW)

    assert (
        should_send(
            [Problem("xray down", ""), Problem("hysteria down", "")],
            state,
            NOW + timedelta(minutes=20),
        )
        is True
    )


def test_recovery_is_reported(tmp_path: Path) -> None:
    """ "It is fixed" is the other half of an alert. Without it the only way to
    learn is to go and look, which is the habit this exists to remove."""

    state = tmp_path / "state"
    should_send([Problem("xray down", "")], state, NOW)

    assert should_send([], state, NOW + timedelta(minutes=20)) is True


def test_a_healthy_system_stays_silent(tmp_path: Path) -> None:
    state = tmp_path / "state"

    assert should_send([], state, NOW) is False
    assert should_send([], state, NOW + timedelta(days=2)) is False


def test_an_unwritable_state_file_duplicates_rather_than_suppresses(tmp_path: Path) -> None:
    """Losing the state costs a repeated alert. The alternative -- treating a
    write failure as "already sent" -- would suppress a real one."""

    state = tmp_path / "missing-dir" / "nested" / "state"
    assert should_send([Problem("xray down", "")], state, NOW) is True


# --- the message itself -----------------------------------------------------


def test_the_subject_names_the_problem_not_just_the_host() -> None:
    """A subject line that says only "alert" makes triage require opening it."""

    subject, _ = compose([Problem("nebula-xray is crash looping", "detail")], "vpn1")

    assert "nebula-xray is crash looping" in subject


def test_several_problems_are_counted_in_the_subject() -> None:
    subject, body = compose(
        [Problem("a", "detail a"), Problem("b", "detail b"), Problem("c", "detail c")], "vpn1"
    )

    assert "3 problems" in subject
    assert "detail c" in body, "every problem's detail must survive into the body"


def test_the_recovery_message_says_nothing_is_needed() -> None:
    subject, body = compose([], "vpn1")

    assert "recovered" in subject
    assert "Nothing further" in body


def test_settings_carry_no_alert_recipient_by_default() -> None:
    """Mail must be opted into. A default recipient would either be wrong or
    would be someone else's inbox."""

    settings = Settings(env="test")

    assert settings.alert_recipient is None
    assert settings.alert_api_key_file is None
    assert settings.alert_state_file == PurePosixPath("/var/lib/nebula/healthcheck.state")


# --- containers ------------------------------------------------------------
#
# The usage container enforces allowances and ends lapsed access every fifteen
# seconds. Docker restarts it and marks it unhealthy, and neither tells anyone.


def _docker_answering(
    monkeypatch: pytest.MonkeyPatch, inspect: str | None, logs: str = "last lines"
) -> list[list[str]]:
    calls: list[list[str]] = []

    def _fake(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
        calls.append(argv)
        if argv[1] == "inspect":
            if inspect is None:
                return subprocess.CompletedProcess(argv, 1, "", "No such object")
            return subprocess.CompletedProcess(argv, 0, inspect + "\n", "")
        return subprocess.CompletedProcess(argv, 0, logs + "\n", "")

    monkeypatch.setattr(healthcheck, "_run", _fake)
    return calls


def test_a_running_healthy_container_is_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _docker_answering(monkeypatch, "running healthy")
    assert healthcheck.check_containers_are_healthy() == []
    assert [call[-1] for call in calls if call[1] == "inspect"] == [
        "nebula-production-usage-1",
        "nebula-production-worker-1",
    ]


def test_a_container_still_starting_is_given_time(monkeypatch: pytest.MonkeyPatch) -> None:
    # Just recreated by a deploy: no pass has had time to finish.
    _docker_answering(monkeypatch, "running starting")
    assert healthcheck.check_containers_are_healthy() == []


def test_an_unhealthy_container_is_reported_with_its_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _docker_answering(
        monkeypatch, "running unhealthy", logs="A usage pass failed: OperationalError."
    )

    problems = healthcheck.check_containers_are_healthy()

    assert [problem.subject for problem in problems] == [
        "nebula-production-usage-1 is unhealthy",
        "nebula-production-worker-1 is unhealthy",
    ]
    assert "A usage pass failed: OperationalError." in problems[0].detail


def test_a_container_that_is_not_running_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    _docker_answering(monkeypatch, "restarting ")

    problems = healthcheck.check_containers_are_healthy()

    assert [problem.subject for problem in problems] == [
        "nebula-production-usage-1 is restarting",
        "nebula-production-worker-1 is restarting",
    ]


def test_a_missing_container_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    # Removed, or never recreated after a deploy that dropped it.
    _docker_answering(monkeypatch, None)

    problems = healthcheck.check_containers_are_healthy()

    assert [problem.subject for problem in problems] == [
        "nebula-production-usage-1 could not be found",
        "nebula-production-worker-1 could not be found",
    ]


def test_docker_itself_failing_is_reported_rather_than_assumed_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(healthcheck, "_run", lambda _argv: None)

    problems = healthcheck.check_containers_are_healthy()

    assert len(problems) == 2


def test_a_container_without_a_health_check_passes_on_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _docker_answering(monkeypatch, "running ")
    assert healthcheck.check_containers_are_healthy() == []
