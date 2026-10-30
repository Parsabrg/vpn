"""Periodic supervision, and the reason it is periodic rather than event-driven.

Nothing in this deployment reported a fault until a person noticed one. A bad
config restarted Hysteria2 25,126 times, XHTTP advertised a dead endpoint from
the day it was written, and a certificate expired -- all while every unit read
as active.

`OnFailure=` handles part of that and cannot handle the rest, which is why both
exist:

- A crash loop never reaches `failed`. The start-rate limit on nebula-xray and
  nebula-hysteria is deliberately huge, because restarts are also how config is
  applied, so a unit restarting every fifteen seconds forever never trips it
  and never enters a failed state for OnFailure to catch.
- A timer that stops firing produces no failure at all. There is no event; the
  absence is the fault, and only something asking can see it.
- A certificate expiring is not a unit failure either.

That last class is why this matters more than it did before the revocation
cascade landed. Revoking a device now marks its credentials REVOKING and hands
them to nebula-reconcile.timer to remove from the server. If that timer quietly
stops, revocations stop completing and access continues indefinitely, while
every screen shows the device as revoked. A background repair job became a
load-bearing security control, so it needs a dead man's switch.
"""

import asyncio
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from nebula_agent.alerting import AlertNotSent, Mailer, ping_dead_man_switch
from nebula_agent.drivers.xray import _SYSTEMCTL_BINARY
from nebula_agent.preflight import (
    check_advertised_endpoints,
    check_units_are_not_crash_looping,
)
from nebula_agent.settings import Settings, get_settings

_JOURNALCTL_BINARY = "/usr/bin/journalctl"
_DOCKER_BINARY = "/usr/bin/docker"
_OPENSSL_BINARY = "/usr/bin/openssl"

# How stale a timer's last run may be before it counts as stopped. Generous
# multiples of each cadence: the point is to catch a timer that has stopped,
# not to wake someone because a sweep ran a few minutes late.
_RECONCILE_MAX_AGE = timedelta(hours=1)  # fires every 15 minutes
_BACKUP_MAX_AGE = timedelta(hours=36)  # fires daily, with up to 30m of jitter

# Certbot renews at 30 days remaining, so anything under 14 means renewal has
# been failing for a fortnight with nobody told.
_CERT_WARN_DAYS = 14

_UNITS = ("nebula-vpn-agent", "nebula-xray", "nebula-hysteria")

# Containers whose failure produces no event anywhere else. `usage` enforces
# traffic allowances and ends lapsed or revoked access every fifteen seconds;
# Docker restarts it if it exits, and marks it unhealthy if it stops finishing
# passes, but neither reaches a person. The API has its own checks: the
# advertised endpoints stop answering when it is down.
#
# `worker` is here for the same reason: it delivers every activation and
# password-reset email, and a worker wedged on a provider that never answers
# looks exactly like one with nothing to send. Nobody notices until somebody
# cannot get into their account.
_CONTAINERS = ("nebula-production-usage-1", "nebula-production-worker-1")
_TIMERS = {
    "nebula-reconcile.timer": _RECONCILE_MAX_AGE,
    "nebula-backup.timer": _BACKUP_MAX_AGE,
}


@dataclass(frozen=True, slots=True)
class Problem:
    subject: str
    detail: str


def _run(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(  # noqa: S603 - fixed binaries, no shell, literal args
            argv, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _systemctl(*args: str) -> str | None:
    result = _run([_SYSTEMCTL_BINARY, *args])
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip()


def _journal_tail(unit: str, lines: int = 20) -> str:
    result = _run([_JOURNALCTL_BINARY, "-u", unit, "-n", str(lines), "--no-pager"])
    if result is None:
        return "(journal unavailable)"
    return result.stdout.strip() or "(no journal output)"


def check_timers_are_still_firing(now: datetime) -> list[Problem]:
    """A timer that stopped is silent by nature, so it has to be asked."""

    problems: list[Problem] = []
    for timer, max_age in _TIMERS.items():
        raw = _systemctl("show", "-p", "LastTriggerUSec", "--value", timer)
        if raw is None:
            problems.append(
                Problem(f"{timer} could not be queried", "systemctl show failed for this timer")
            )
            continue
        if not raw or raw in {"0", "n/a"}:
            problems.append(
                Problem(
                    f"{timer} has never fired",
                    "The timer is installed but has no recorded trigger. If it was "
                    "only just enabled, this clears itself on the next run.",
                )
            )
            continue
        last = _parse_timestamp(raw)
        if last is None:
            problems.append(Problem(f"{timer} timestamp was not understood", raw))
            continue
        age = now - last
        if age > max_age:
            problems.append(
                Problem(
                    f"{timer} has not fired in {age}",
                    f"Last trigger {last:%Y-%m-%d %H:%M} UTC, older than the {max_age} "
                    "this check allows.",
                )
            )
    return problems


def _parse_timestamp(raw: str) -> datetime | None:
    """systemd prints 'Thu 2026-09-04 10:15:00 UTC'."""

    cleaned = raw.split(" UTC")[0].strip()
    try:
        return datetime.strptime(cleaned, "%a %Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def check_units_are_active() -> list[Problem]:
    problems: list[Problem] = []
    for unit in _UNITS:
        state = _systemctl("is-active", unit)
        if state != "active":
            problems.append(Problem(f"{unit} is {state or 'not reporting'}", _journal_tail(unit)))
    return problems


def check_containers_are_healthy() -> list[Problem]:
    """A container Docker keeps restarting, or reports unhealthy, fails
    silently: nothing else watches it.

    `starting` passes: a container that has just been recreated has not had
    time to finish a pass, and the next run looks again. A container with no
    health check passes on running alone.
    """

    problems: list[Problem] = []
    for name in _CONTAINERS:
        result = _run(
            [
                _DOCKER_BINARY,
                "inspect",
                "--format",
                "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                name,
            ]
        )
        if result is None or result.returncode != 0:
            problems.append(
                Problem(
                    f"{name} could not be found",
                    "docker inspect did not find this background service.",
                )
            )
            continue
        status, _, health = result.stdout.strip().partition(" ")
        if status != "running":
            problems.append(
                Problem(f"{name} is {status or 'not reporting'}", _docker_logs_tail(name))
            )
        elif health == "unhealthy":
            problems.append(
                Problem(
                    f"{name} is unhealthy",
                    "Its health check has not completed successfully.\n\n"
                    + _docker_logs_tail(name),
                )
            )
    return problems


def _docker_logs_tail(name: str, lines: int = 20) -> str:
    result = _run([_DOCKER_BINARY, "logs", "--tail", str(lines), name])
    if result is None:
        return "(logs unavailable)"
    # The loop prints to stdout and a crash lands on stderr.
    return (result.stdout + result.stderr).strip() or "(no log output)"


def check_certificates(settings: Settings, now: datetime) -> list[Problem]:
    """Expiry is not a unit failure, so nothing else here would notice it.

    Parsed with openssl rather than a library: this runs on the host outside
    any container, and pulling in a dependency to read a date that
    `openssl x509 -enddate` already prints is not worth the install.
    """

    cert = settings.xray_tls_cert_file
    if cert is None:
        return []
    path = Path(str(cert))
    if not path.exists():
        return [Problem(f"{path} is missing", "The TLS certificate the transports serve is gone.")]
    result = _run([_OPENSSL_BINARY, "x509", "-in", str(path), "-noout", "-enddate"])
    if result is None:
        return [Problem(f"{path} could not be read", "openssl was not runnable")]
    if result.returncode != 0:
        return [Problem(f"{path} could not be parsed", result.stderr.strip())]
    raw = result.stdout.strip().removeprefix("notAfter=")
    try:
        expires = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return [Problem(f"{path} expiry was not understood", raw)]
    remaining = expires - now
    if remaining < timedelta(days=_CERT_WARN_DAYS):
        return [
            Problem(
                f"TLS certificate expires in {remaining.days} days",
                f"{path} is valid until {expires:%Y-%m-%d}. Certbot renews at 30 days "
                "remaining, so this means renewal has been failing.",
            )
        ]
    return []


async def collect_problems(settings: Settings, now: datetime) -> list[Problem]:
    problems: list[Problem] = []
    problems.extend(check_timers_are_still_firing(now))
    problems.extend(check_units_are_active())
    problems.extend(check_containers_are_healthy())
    problems.extend(check_certificates(settings, now))

    for unit, healthy, detail in await check_units_are_not_crash_looping():
        if healthy is False:
            problems.append(Problem(f"{unit} is crash looping", detail))

    for result in await check_advertised_endpoints(settings):
        if result.reachable is False:
            problems.append(
                Problem(
                    f"{result.protocol_profile_code} is advertised but does not answer",
                    f"Clients are told to dial {result.host}:{result.port} "
                    f"({result.transport}), which {result.detail}. They will report a "
                    "working tunnel and pass no traffic.",
                )
            )
    return problems


def should_send(problems: list[Problem], state_file: Path, now: datetime) -> bool:
    """Send when the set of problems changes, and once a day while it persists.

    Every run would mail every fifteen minutes for as long as something is
    wrong, and a mailbox like that gets filtered within a week -- at which
    point this is worse than no monitoring, because it looks like monitoring.
    Never re-sending is the opposite failure: a fault reported once at 3am and
    never again is one nobody acts on.

    Recovery is reported too. "It is fixed" is the other half of an alert, and
    without it the only way to learn is to go and look, which is the habit this
    exists to remove.
    """

    fingerprint = "\n".join(sorted(problem.subject for problem in problems))
    previous, sent_at = _read_state(state_file)
    if fingerprint != previous:
        _write_state(state_file, fingerprint, now)
        # A transition into healthy is worth one message; staying healthy is not.
        return bool(problems) or bool(previous)
    if problems and (sent_at is None or now - sent_at >= timedelta(days=1)):
        _write_state(state_file, fingerprint, now)
        return True
    return False


def _read_state(state_file: Path) -> tuple[str, datetime | None]:
    try:
        raw = state_file.read_text(encoding="utf-8")
    except OSError:
        return "", None
    head, _, body = raw.partition("\n")
    try:
        sent_at = datetime.fromisoformat(head)
    except ValueError:
        return body, None
    return body, sent_at


def _write_state(state_file: Path, fingerprint: str, now: datetime) -> None:
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(f"{now.isoformat()}\n{fingerprint}", encoding="utf-8")
    except OSError:
        # Losing the state file costs a duplicate alert, which is the right
        # way round: the alternative is suppressing a real one.
        pass


def compose(problems: list[Problem], host: str) -> tuple[str, str]:
    if not problems:
        return (
            f"[nebula] {host} recovered",
            "Every check passes again. Nothing further is needed.",
        )
    subject = f"[nebula] {host}: {problems[0].subject}"
    if len(problems) > 1:
        subject = f"[nebula] {host}: {len(problems)} problems, first is {problems[0].subject}"
    lines = [f"{len(problems)} problem(s) on {host}.", ""]
    for problem in problems:
        lines.append(f"--- {problem.subject}")
        lines.append(problem.detail)
        lines.append("")
    lines.append("Runbook: docs/runbooks/monitoring.md")
    return subject, "\n".join(lines)


def main() -> None:
    settings = get_settings()
    now = datetime.now(UTC)
    problems = asyncio.run(collect_problems(settings, now))

    for problem in problems:
        print(f"[PROBLEM] {problem.subject}", file=sys.stderr)
    if not problems:
        print("all checks pass")

    # Before the email, and outside its success or failure. This is the report
    # that has to survive the mail path being broken, and the only one whose
    # absence is itself the alert -- so it must not sit behind a `return` that
    # a de-duplicated email would take.
    if settings.deadman_url is not None:
        ping_dead_man_switch(settings.deadman_url, healthy=not problems)
        print(f"dead man's switch pinged ({'ok' if not problems else 'fail'})")

    if not should_send(problems, Path(str(settings.alert_state_file)), now):
        return
    if (
        settings.alert_recipient is None
        or settings.alert_api_key_file is None
        or settings.alert_sender is None
    ):
        raise SystemExit(
            "there is something to report but no alert recipient is configured; "
            "set NEBULA_ALERT_RECIPIENT and NEBULA_ALERT_API_KEY_FILE"
        )
    subject, body = compose(problems, settings.alert_hostname)
    mailer = Mailer.from_files(
        Path(str(settings.alert_api_key_file)),
        settings.alert_sender,
        settings.alert_recipient,
    )
    try:
        message_id = mailer.send(subject=subject, body=body)
    except AlertNotSent as error:
        # Exit non-zero so the unit fails and OnFailure fires, which at least
        # leaves a failed unit behind. A monitor that cannot report and says
        # nothing is the exact failure mode this whole thing exists to remove.
        raise SystemExit(f"alert could not be sent: {error}") from error
    print(f"alert sent ({message_id})")


def alert_unit_main() -> None:
    """The OnFailure= entry point: report that one named unit failed.

    Takes the unit name as its only argument, because systemd expands %n into
    it. Sends unconditionally rather than through should_send(): a unit
    entering `failed` is an edge, not a level, so there is nothing to
    de-duplicate and suppressing it would be suppressing the only notice.
    """

    unit = sys.argv[1] if len(sys.argv) > 1 else "an unnamed unit"
    settings = get_settings()
    if (
        settings.alert_recipient is None
        or settings.alert_api_key_file is None
        or settings.alert_sender is None
    ):
        raise SystemExit(
            f"{unit} failed, and no alert recipient is configured to report it; "
            "set NEBULA_ALERT_RECIPIENT and NEBULA_ALERT_API_KEY_FILE"
        )
    body = "\n".join(
        [
            f"{unit} entered a failed state on {settings.alert_hostname}.",
            "",
            "Last 20 journal lines:",
            "",
            _journal_tail(unit),
            "",
            "Runbook: docs/runbooks/monitoring.md",
        ]
    )
    mailer = Mailer.from_files(
        Path(str(settings.alert_api_key_file)),
        settings.alert_sender,
        settings.alert_recipient,
    )
    try:
        message_id = mailer.send(
            subject=f"[nebula] {settings.alert_hostname}: {unit} failed", body=body
        )
    except AlertNotSent as error:
        raise SystemExit(f"alert could not be sent: {error}") from error
    print(f"alert sent ({message_id})")


if __name__ == "__main__":
    main()
