"""The certificate check, unit liveness, and both command entry points.

Separated from test_healthcheck.py, which covers the decision logic: these
need a settings object and a stubbed mailer, and mixing the two made the
fixtures in both harder to follow.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import ClassVar

import pytest

from nebula_agent import healthcheck
from nebula_agent.alerting import AlertNotSent
from nebula_agent.healthcheck import Problem
from nebula_agent.settings import Settings

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)

# String target: mypy runs with no_implicit_reexport, so reaching sys through
# the module under test is an error even though that is what is being patched.
_ARGV = "nebula_agent.healthcheck.sys.argv"


class _Result:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _systemctl_returning(monkeypatch: pytest.MonkeyPatch, answers: dict[str, str | None]) -> None:
    monkeypatch.setattr(healthcheck, "_systemctl", lambda *args: answers.get(args[-1]))


def _openssl_returning(monkeypatch: pytest.MonkeyPatch, stdout: str, returncode: int = 0) -> None:
    monkeypatch.setattr(healthcheck, "_run", lambda _argv: _Result(stdout, returncode))


class _Mailer:
    """Records what would have been sent, so the tests assert on the message a
    person receives rather than on the fact that send() was reached."""

    sent: ClassVar[dict[str, str]] = {}

    @classmethod
    def from_files(cls, *_args: object) -> "_Mailer":
        return cls()

    def send(self, *, subject: str, body: str) -> str:
        _Mailer.sent = {"subject": subject, "body": body}
        return "msg_1"


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base: dict[str, object] = {"alert_state_file": PurePosixPath(str(tmp_path / "state"))}
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


def _problems(monkeypatch: pytest.MonkeyPatch, problems: list[Problem]) -> None:
    async def _collect(*_a: object, **_k: object) -> list[Problem]:
        return problems

    monkeypatch.setattr(healthcheck, "collect_problems", _collect)


# --- certificates -----------------------------------------------------------
#
# An expired certificate is not a unit failure, so nothing else here sees one.
# One expired on this deployment and was found by a person.


def _cert_settings(tmp_path: Path) -> Settings:
    cert = tmp_path / "cert.pem"
    cert.write_text("not really a certificate")
    return _settings(tmp_path, xray_tls_cert_file=PurePosixPath(str(cert)))


def test_a_certificate_with_months_left_is_healthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    far = (NOW + timedelta(days=80)).strftime("%b %d %H:%M:%S %Y GMT")
    _openssl_returning(monkeypatch, f"notAfter={far}\n")

    assert healthcheck.check_certificates(_cert_settings(tmp_path), NOW) == []


def test_a_certificate_expiring_soon_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Certbot renews at 30 days remaining, so under 14 means renewal has been
    failing for a fortnight with nobody told."""

    soon = (NOW + timedelta(days=9)).strftime("%b %d %H:%M:%S %Y GMT")
    _openssl_returning(monkeypatch, f"notAfter={soon}\n")

    problems = healthcheck.check_certificates(_cert_settings(tmp_path), NOW)

    assert len(problems) == 1
    assert "expires in 9 days" in problems[0].subject


def test_an_unparseable_expiry_is_reported_rather_than_assumed_healthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _openssl_returning(monkeypatch, "notAfter=whenever\n")

    problems = healthcheck.check_certificates(_cert_settings(tmp_path), NOW)

    assert len(problems) == 1
    assert "not understood" in problems[0].subject


def test_openssl_failing_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _openssl_returning(monkeypatch, "", returncode=1)

    problems = healthcheck.check_certificates(_cert_settings(tmp_path), NOW)

    assert len(problems) == 1
    assert "could not be parsed" in problems[0].subject


def test_a_missing_certificate_file_is_reported(tmp_path: Path) -> None:
    settings = _settings(tmp_path, xray_tls_cert_file=PurePosixPath(str(tmp_path / "absent.pem")))

    problems = healthcheck.check_certificates(settings, NOW)

    assert len(problems) == 1
    assert "is missing" in problems[0].subject


def test_no_configured_certificate_is_not_a_problem(tmp_path: Path) -> None:
    """A deployment without TLS configured is a valid state, not a fault."""

    assert healthcheck.check_certificates(_settings(tmp_path), NOW) == []


# --- unit liveness ----------------------------------------------------------


def test_an_inactive_unit_is_reported_with_its_journal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The journal tail is the point. An alert saying only "nebula-xray is
    failed" sends someone to SSH before they know anything."""

    _systemctl_returning(
        monkeypatch,
        {"nebula-vpn-agent": "active", "nebula-xray": "failed", "nebula-hysteria": "active"},
    )
    monkeypatch.setattr(healthcheck, "_journal_tail", lambda _u, lines=20: "config parse error")

    problems = healthcheck.check_units_are_active()

    assert [p.subject for p in problems] == ["nebula-xray is failed"]
    assert problems[0].detail == "config parse error"


def test_a_unit_that_cannot_be_queried_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unknown is not the same as fine."""

    _systemctl_returning(monkeypatch, {})
    monkeypatch.setattr(healthcheck, "_journal_tail", lambda _u, lines=20: "")

    assert len(healthcheck.check_units_are_active()) == 3


# --- the health check command ------------------------------------------------


def test_the_command_is_quiet_and_zero_when_everything_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(healthcheck, "get_settings", lambda: _settings(tmp_path))
    _problems(monkeypatch, [])

    healthcheck.main()

    assert "all checks pass" in capsys.readouterr().out


def test_the_command_refuses_to_stay_quiet_when_it_cannot_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Something is wrong and no recipient is configured. Exiting non-zero
    makes the unit fail, which is at least visible; returning 0 would leave a
    deployment that looks monitored while nothing is watching."""

    monkeypatch.setattr(healthcheck, "get_settings", lambda: _settings(tmp_path))
    _problems(monkeypatch, [Problem("nebula-xray is failed", "detail")])

    with pytest.raises(SystemExit, match="no alert recipient"):
        healthcheck.main()


def test_the_command_sends_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(healthcheck, "get_settings", lambda: _configured(tmp_path))
    _problems(monkeypatch, [Problem("nebula-xray is failed", "why it failed")])
    monkeypatch.setattr(healthcheck, "Mailer", _Mailer)

    healthcheck.main()

    assert "nebula-xray is failed" in _Mailer.sent["subject"]
    assert "why it failed" in _Mailer.sent["body"]
    assert "alert sent" in capsys.readouterr().out


def test_a_failed_send_fails_the_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A monitor that cannot report and says nothing is the exact failure mode
    this exists to remove, so it exits non-zero and trips its own OnFailure."""

    monkeypatch.setattr(healthcheck, "get_settings", lambda: _configured(tmp_path))
    _problems(monkeypatch, [Problem("nebula-xray is failed", "detail")])

    class _BrokenMailer(_Mailer):
        def send(self, *, subject: str, body: str) -> str:
            raise AlertNotSent("Resend delivery failed")

    monkeypatch.setattr(healthcheck, "Mailer", _BrokenMailer)

    with pytest.raises(SystemExit, match="could not be sent"):
        healthcheck.main()


def test_the_command_does_not_resend_an_unchanged_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Twenty minutes apart, forever, is how a monitoring mailbox gets filtered
    -- at which point this is worse than nothing, because it looks like
    monitoring."""

    monkeypatch.setattr(healthcheck, "get_settings", lambda: _configured(tmp_path))
    _problems(monkeypatch, [Problem("nebula-xray is failed", "detail")])
    monkeypatch.setattr(healthcheck, "Mailer", _Mailer)

    healthcheck.main()
    _Mailer.sent = {}
    healthcheck.main()

    assert _Mailer.sent == {}, "the second run must not send the same alert again"


# --- the OnFailure= entry point ----------------------------------------------


def test_the_onfailure_entry_point_reports_the_named_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(healthcheck, "get_settings", lambda: _configured(tmp_path))
    monkeypatch.setattr(_ARGV, ["nebula-agent-alert", "nebula-backup.service"])
    monkeypatch.setattr(healthcheck, "_journal_tail", lambda _u, lines=20: "b2 upload refused")
    monkeypatch.setattr(healthcheck, "Mailer", _Mailer)
    _Mailer.sent = {}

    healthcheck.alert_unit_main()

    assert "nebula-backup.service failed" in _Mailer.sent["subject"]
    assert "b2 upload refused" in _Mailer.sent["body"], "the journal tail must reach the reader"


def test_the_onfailure_entry_point_fails_loudly_without_a_recipient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(healthcheck, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(_ARGV, ["nebula-agent-alert", "nebula-xray.service"])

    with pytest.raises(SystemExit, match="no alert recipient"):
        healthcheck.alert_unit_main()


# --- the dead man's switch, wired into the command ---------------------------


def _pings(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    seen: list[bool] = []
    monkeypatch.setattr(
        healthcheck, "ping_dead_man_switch", lambda _url, *, healthy: seen.append(healthy)
    )
    return seen


def test_a_healthy_run_pings_the_switch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        healthcheck, "get_settings", lambda: _settings(tmp_path, deadman_url="https://hc/x")
    )
    _problems(monkeypatch, [])
    seen = _pings(monkeypatch)

    healthcheck.main()

    assert seen == [True]


def test_the_switch_is_pinged_even_when_the_email_is_suppressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the whole mechanism. Emails de-duplicate to once a day
    while a problem stands, and the ping must not sit behind that: an external
    service that stops hearing from us is how a dead host is noticed, and a
    host with a standing problem is exactly when it might die.
    """

    settings = _configured(tmp_path).model_copy(update={"deadman_url": "https://hc/x"})
    monkeypatch.setattr(healthcheck, "get_settings", lambda: settings)
    _problems(monkeypatch, [Problem("nebula-xray is failed", "detail")])
    monkeypatch.setattr(healthcheck, "Mailer", _Mailer)
    seen = _pings(monkeypatch)

    healthcheck.main()  # first run: email sent
    healthcheck.main()  # second run: email de-duplicated away

    assert seen == [False, False], "the ping must fire on both runs"


def test_the_switch_is_pinged_even_when_the_email_cannot_be_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resend being down is one of the failures this exists to survive, so the
    ping has to happen before the mail is attempted rather than after it."""

    settings = _configured(tmp_path).model_copy(update={"deadman_url": "https://hc/x"})
    monkeypatch.setattr(healthcheck, "get_settings", lambda: settings)
    _problems(monkeypatch, [Problem("nebula-xray is failed", "detail")])
    seen = _pings(monkeypatch)

    class _BrokenMailer(_Mailer):
        def send(self, *, subject: str, body: str) -> str:
            raise AlertNotSent("Resend delivery failed")

    monkeypatch.setattr(healthcheck, "Mailer", _BrokenMailer)

    with pytest.raises(SystemExit):
        healthcheck.main()

    assert seen == [False], "the failure ping must already have gone out"


def test_the_switch_is_pinged_even_with_no_recipient_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deployment using only the external service, with no mail set up at
    all, is a reasonable configuration and must still report."""

    monkeypatch.setattr(
        healthcheck, "get_settings", lambda: _settings(tmp_path, deadman_url="https://hc/x")
    )
    _problems(monkeypatch, [Problem("nebula-xray is failed", "detail")])
    seen = _pings(monkeypatch)

    with pytest.raises(SystemExit, match="no alert recipient"):
        healthcheck.main()

    assert seen == [False]


def test_no_configured_switch_pings_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(healthcheck, "get_settings", lambda: _settings(tmp_path))
    _problems(monkeypatch, [])
    seen = _pings(monkeypatch)

    healthcheck.main()

    assert seen == []
