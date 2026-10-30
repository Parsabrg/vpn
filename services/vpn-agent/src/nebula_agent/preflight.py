"""Dial every endpoint this agent advertises, and say which ones answer.

Two transports have shipped advertising an endpoint that nothing answered on.
XHTTP told every client to dial a loopback port with TLS disabled, and did so
from the day it was written; Hysteria2 ran without the obfuscation it claimed.
Both looked healthy from the server: the process was up, the config was valid,
the unit was active, and provisioning returned success. What was actually
wrong could only be seen by connecting the way a client does.

Nothing in the system did that. This does.

It deliberately asks the driver what it advertises instead of recomputing the
endpoint from settings. A check that derives the address itself would derive
it with the same mistake and agree with the bug -- which is what every
server-side investigation of the XHTTP fault did.

Run it after any change to inbounds, TLS, or the firewall:

    /opt/nebula-vpn-agent/.venv/bin/nebula-agent-check
"""

import asyncio
import socket
import sys
from dataclasses import dataclass

from nebula_agent.driver_factory import build_xray_driver
from nebula_agent.drivers.xray import _HYSTERIA_UNIT, _SYSTEMCTL_BINARY, _XRAY_UNIT
from nebula_agent.settings import Settings, get_settings

# Long enough to cross a real network and back, short enough that checking a
# handful of dead ports does not look like a hang.
_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class EndpointCheck:
    protocol_profile_code: str
    host: str
    port: int
    transport: str
    reachable: bool | None  # None: cannot be checked this way, see `detail`
    detail: str

    @property
    def status(self) -> str:
        if self.reachable is None:
            return "SKIP"
        return "OK" if self.reachable else "FAIL"


# Hysteria2 is QUIC over UDP. A UDP socket accepts a connect() and sends into
# the void whether or not anything listens, so "it connected" proves nothing
# and a real check would have to speak the protocol. Reported honestly as
# unchecked rather than passed off as healthy.
_UDP_TRANSPORTS = frozenset({"hysteria"})


async def _probe(host: str, port: int) -> tuple[bool, str]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_TIMEOUT_SECONDS
        )
    except TimeoutError:
        return False, f"no answer within {_TIMEOUT_SECONDS:g}s (filtered, or nothing listening)"
    except (OSError, socket.gaierror) as error:
        return False, f"{type(error).__name__}: {error}"
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True, "accepted a connection"


async def check_advertised_endpoints(
    settings: Settings, driver: object | None = None
) -> tuple[EndpointCheck, ...]:
    # The same builder main.py uses, so this checks the driver the agent
    # actually serves with rather than one assembled to match. The parameter
    # is for tests, which need a driver with known-dead endpoints.
    driver = driver if driver is not None else build_xray_driver(settings)
    advertised = getattr(driver, "advertised_endpoints", None)
    if advertised is None:
        raise SystemExit(
            f"the configured driver ({type(driver).__name__}) does not serve real endpoints; "
            "check NEBULA_XRAY_DRIVER on this host"
        )
    results = []
    for code, host, port, transport in advertised():
        if transport in _UDP_TRANSPORTS:
            results.append(
                EndpointCheck(code, host, port, transport, None, "UDP; not checkable by connecting")
            )
            continue
        reachable, detail = await _probe(host, port)
        if not reachable:
            # One more try before calling it dead: a host connecting to its own
            # public address lost one connection in five at times (2026-10-26)
            # while outside clients connected every time.
            reachable, detail = await _probe(host, port)
        results.append(EndpointCheck(code, host, port, transport, reachable, detail))
    return tuple(results)


# Long enough that a loop restarting every 15s is very likely to tick once,
# short enough to keep a manual check interactive.
_LOOP_SAMPLE_SECONDS = 20.0


async def _restart_count(unit: str) -> int | None:
    """None means "could not ask", which every caller reports as unknown.

    The spawn is guarded, not just the exit code: on a host with no systemctl
    at all -- a container, a non-systemd distribution, a developer machine --
    create_subprocess_exec raises rather than returning non-zero, and an
    uncaught raise there would take down the health check that was in the
    middle of reporting real problems.
    """

    try:
        process = await asyncio.create_subprocess_exec(
            _SYSTEMCTL_BINARY,
            "show",
            "-p",
            "NRestarts",
            "--value",
            unit,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await process.communicate()
    except (OSError, ValueError):
        return None
    if process.returncode != 0:
        return None
    try:
        return int(stdout.decode().strip())
    except ValueError:
        return None


async def check_units_are_not_crash_looping() -> tuple[tuple[str, bool | None, str], ...]:
    """Sample each unit's restart counter twice and see if it moved.

    A crash loop is invisible from `systemctl is-active`: the unit reports
    active between exits, and the restart budget here is deliberately large
    because restarts are also how config is applied, so the loop never trips
    a limit and never latches into `failed`. One bad config restarted
    Hysteria2 25,126 times on that basis without anything reporting a problem.

    A raw restart count cannot distinguish that from normal operation, since
    every provision restarts these units too. Two samples can: a counter that
    moves while nothing is being provisioned is a loop, and it is the one
    reading that means the same thing on both units.
    """

    units = (_XRAY_UNIT, _HYSTERIA_UNIT)
    results: list[tuple[str, bool | None, str]] = []
    first = {unit: await _restart_count(unit) for unit in units}
    await asyncio.sleep(_LOOP_SAMPLE_SECONDS)

    for unit in units:
        before, after = first[unit], await _restart_count(unit)
        if before is None or after is None:
            results.append((unit, None, "restart count unavailable (not a systemd host?)"))
        elif after > before:
            results.append(
                (
                    unit,
                    False,
                    f"restarted {after - before}x in {_LOOP_SAMPLE_SECONDS:g}s "
                    f"({before} -> {after} total) -- crash looping",
                )
            )
        else:
            results.append((unit, True, f"stable ({after} restarts total, none during the check)"))
    return tuple(results)


def main() -> None:
    results = asyncio.run(check_advertised_endpoints(get_settings()))
    for result in results:
        print(
            f"[{result.status:4}] {result.protocol_profile_code:32} "
            f"{result.host}:{result.port} ({result.transport}) -- {result.detail}"
        )

    print(f"\nWatching for crash loops for {_LOOP_SAMPLE_SECONDS:g}s...")
    loops = asyncio.run(check_units_are_not_crash_looping())
    for unit, healthy, detail in loops:
        status = "SKIP" if healthy is None else ("OK" if healthy else "FAIL")
        print(f"[{status:4}] {unit:32} -- {detail}")

    failed = [result for result in results if result.reachable is False]
    looping = [unit for unit, healthy, _ in loops if healthy is False]
    if failed:
        print(
            f"\n{len(failed)} advertised endpoint(s) did not answer. Clients told to dial "
            "these will report a working tunnel and pass no traffic.",
            file=sys.stderr,
        )
    if looping:
        print(
            f"\n{len(looping)} unit(s) are restarting on a loop. They read as active "
            "between exits, so nothing else reports this.",
            file=sys.stderr,
        )
    if failed or looping:
        raise SystemExit(1)
    print(f"\nAll {len(results)} advertised endpoint(s) answered; no unit is crash looping.")


if __name__ == "__main__":
    main()
