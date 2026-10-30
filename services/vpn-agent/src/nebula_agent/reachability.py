"""Is the server reachable from Iran, which is the only place it matters.

Every other check here runs on the VPS and answers "is this server healthy".
None of them can answer the question the users actually have, which is whether
the server is reachable *through the censor*. A transport can be perfectly
served and completely unusable, and from the server those look identical.

This asks probes inside Iran. It uses Globalping, which needs no account and
has five probes in Tehran across four networks.

## What it measures, and what it cannot

It runs a **TCP traceroute** to each advertised port and asks whether the last
hop is the server's own address. That detects the blocking that is total and
common: the IP null-routed, the port dropped at the border, the route
withdrawn.

It deliberately does **not** speak the real protocol, and cannot. Iranian
filtering increasingly works by fingerprinting the handshake itself, and a
VLESS or REALITY session being torn down by DPI would look identical to a
healthy one here. So a pass means "packets reach the port from Iran", never
"the tunnel works from Iran". Only a real client can answer the second, and
`docs/runbooks/monitoring.md` says so where someone reading a green result
will see it.

The probes are also all `datacenter-network` -- Iranian hosting providers, not
the consumer mobile carriers the app's users are on. Datacenter and eyeball
networks in Iran are filtered differently, so this is a proxy for the users'
experience rather than a measurement of it.

## Why it compares against a control

The first version of this check reported every transport as blocked, from
everywhere, permanently. An HTTPS request to a VLESS inbound is correctly
refused by the server, so "connection closed" was the healthy response being
read as censorship. A control run from outside Iran returned exactly the same
result, which is what caught it.

That is the trap this whole check has to avoid, so the discrimination is built
into the result rather than left to the reader: an endpoint unreachable from
everywhere is a server fault, and only an endpoint unreachable from Iran
*while reachable elsewhere* is evidence of blocking.
"""

import json
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from nebula_agent import __version__
from nebula_agent.alerting import AlertNotSent, Mailer
from nebula_agent.driver_factory import build_xray_driver
from nebula_agent.healthcheck import Problem, compose, should_send
from nebula_agent.settings import get_settings

_API = "https://api.globalping.io/v1/measurements"
_USER_AGENT = f"nebula-agent/{__version__}"

# Generous: a measurement is dispatched to probes and polled, and this runs
# hourly rather than on a hot path.
_TIMEOUT_SECONDS = 30.0
_POLL_ATTEMPTS = 12
_POLL_INTERVAL_SECONDS = 5.0

# Countries used as the control. Several, because one probe having a bad
# minute must not be mistaken for "reachable nowhere", which would turn a
# censorship report into a false server alarm.
_CONTROL_COUNTRIES = ("DE", "NL", "US", "GB")

_IRAN = "IR"

# Hysteria2 is QUIC over UDP. A TCP traceroute to that port measures
# nothing about it, and reporting it blocked on that basis would be a
# fabricated result rather than a missing one.
_UDP_TRANSPORTS = frozenset({"hysteria"})


@dataclass(frozen=True, slots=True)
class PortReachability:
    protocol_profile_code: str
    port: int
    iran_reached: int
    iran_total: int
    control_reached: int
    control_total: int

    @property
    def blocked_from_iran(self) -> bool:
        """No Iranian probe got through, while the control did.

        Both halves are required. Unreachable from everywhere is a server
        fault, which the other checks already report and which this must not
        duplicate as a censorship alert.
        """

        return self.iran_total > 0 and self.iran_reached == 0 and self.control_reached > 0

    @property
    def summary(self) -> str:
        return (
            f"{self.protocol_profile_code} (port {self.port}): "
            f"{self.iran_reached}/{self.iran_total} Iran probes reached the server, "
            f"{self.control_reached}/{self.control_total} elsewhere"
        )


class ProbeUnavailable(Exception):
    """The measurement service could not be used.

    Distinct from "the endpoint is blocked" on purpose: not knowing and being
    blocked are different states, and reporting the first as the second would
    raise a censorship alarm every time an unrelated third party had an outage.
    """


def _post(payload: dict[str, object]) -> str:
    request = urllib.request.Request(
        _API,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
            body = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise ProbeUnavailable(f"could not start a measurement: {error}") from error
    measurement_id = body.get("id") if isinstance(body, dict) else None
    if not isinstance(measurement_id, str):
        raise ProbeUnavailable("measurement response carried no id")
    return measurement_id


def _fetch(measurement_id: str) -> dict[str, object]:
    request = urllib.request.Request(  # noqa: S310 - fixed https constant
        f"{_API}/{measurement_id}", headers={"User-Agent": _USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
            body = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise ProbeUnavailable(f"could not read a measurement: {error}") from error
    if not isinstance(body, dict):
        raise ProbeUnavailable("measurement response was not an object")
    return body


def count_reached(measurement: dict[str, object], server_address: str) -> tuple[int, int]:
    """How many probes' traceroutes ended at the server, and how many ran.

    The last hop is the test. A traceroute that stops short ended at whatever
    dropped it, which for a blocked destination is the border rather than the
    host.
    """

    results = measurement.get("results")
    if not isinstance(results, list):
        return 0, 0
    reached = 0
    for entry in results:
        if not isinstance(entry, dict):
            continue
        result = entry.get("result")
        hops = result.get("hops") if isinstance(result, dict) else None
        if not isinstance(hops, list) or not hops:
            continue
        last = hops[-1]
        if isinstance(last, dict) and last.get("resolvedAddress") == server_address:
            reached += 1
    return reached, len(results)


def _measure(target: str, port: int, countries: tuple[str, ...], limit: int) -> str:
    return _post(
        {
            "type": "traceroute",
            "target": target,
            "limit": limit,
            "locations": [{"country": country} for country in countries],
            "measurementOptions": {"protocol": "TCP", "port": port},
        }
    )


def _await_result(measurement_id: str, sleep: "Callable[[float], None]") -> dict[str, object]:
    for _ in range(_POLL_ATTEMPTS):
        measurement = _fetch(measurement_id)
        if measurement.get("status") != "in-progress":
            return measurement
        sleep(_POLL_INTERVAL_SECONDS)
    raise ProbeUnavailable("measurement did not finish in time")


def check_reachable_from_iran(
    endpoints: "Iterable[tuple[str, str, int, str]]",
    server_address: str,
    *,
    sleep: "Callable[[float], None]" = time.sleep,
) -> list[PortReachability]:
    """One TCP traceroute per advertised TCP port, from Iran and a control.

    UDP transports are skipped rather than guessed at: traceroute over UDP to
    a QUIC port tells you nothing useful, and reporting Hysteria2 as blocked
    on that basis would be worse than saying nothing about it.
    """

    results: list[PortReachability] = []
    for code, _host, port, transport in endpoints:
        if transport in _UDP_TRANSPORTS:
            continue
        iran = _measure(server_address, port, (_IRAN,), 5)
        control = _measure(server_address, port, _CONTROL_COUNTRIES, 4)
        iran_reached, iran_total = count_reached(_await_result(iran, sleep), server_address)
        control_reached, control_total = count_reached(
            _await_result(control, sleep), server_address
        )
        results.append(
            PortReachability(
                protocol_profile_code=code,
                port=port,
                iran_reached=iran_reached,
                iran_total=iran_total,
                control_reached=control_reached,
                control_total=control_total,
            )
        )
    return results


def resolve(host: str) -> str | None:
    """The address a traceroute should end at.

    Resolved here rather than taken from the measurement: if Iranian DNS
    answers with something else, the traceroute ends somewhere that is not
    this server and the endpoint is reported unreachable -- which is the right
    answer, because DNS poisoning is blocking too.
    """

    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def main() -> None:
    settings = get_settings()
    driver = build_xray_driver(settings)
    advertised = getattr(driver, "advertised_endpoints", None)
    if advertised is None:
        raise SystemExit(
            f"the configured driver ({type(driver).__name__}) serves no real endpoints"
        )
    address = resolve(settings.xray_public_host)
    if address is None:
        raise SystemExit(f"could not resolve {settings.xray_public_host}")

    try:
        results = check_reachable_from_iran(advertised(), address)
    except ProbeUnavailable as error:
        # Not knowing is not the same as blocked. Exit non-zero so the unit
        # fails and is reported, but never as a censorship alert.
        raise SystemExit(f"could not measure from Iran: {error}") from error

    for result in results:
        print(f"[{'BLOCKED' if result.blocked_from_iran else 'ok':7}] {result.summary}")

    blocked = [result for result in results if result.blocked_from_iran]
    now = datetime.now(UTC)
    problems = [
        Problem(
            f"{result.protocol_profile_code} is blocked from Iran",
            f"{result.summary}. Packets reach the port from the control probes and "
            "from none in Iran, which is network-level blocking rather than a "
            "server fault. Users on this transport cannot connect; steer them to "
            "one still reachable.",
        )
        for result in blocked
    ]
    if not should_send(problems, Path(str(settings.reachability_state_file)), now):
        return
    if (
        settings.alert_recipient is None
        or settings.alert_api_key_file is None
        or settings.alert_sender is None
    ):
        raise SystemExit("there is something to report but no alert recipient is configured")
    subject, body = compose(problems, f"{settings.alert_hostname} (from Iran)")
    mailer = Mailer.from_files(
        Path(str(settings.alert_api_key_file)), settings.alert_sender, settings.alert_recipient
    )
    try:
        message_id = mailer.send(subject=subject, body=body)
    except AlertNotSent as error:
        raise SystemExit(f"alert could not be sent: {error}") from error
    print(f"alert sent ({message_id})")


if __name__ == "__main__":
    main()
