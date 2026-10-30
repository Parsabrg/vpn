"""Read per-credential byte counters from the three things that serve traffic.

Every source here reports counters that reset -- Xray's on restart, Hysteria's
on restart, WireGuard's when a peer is removed and re-added. This module does
not try to hide that. It reports what the source currently says, and the
control plane accumulates, because only the control plane has somewhere
durable to remember the previous reading. An agent that tried to accumulate
in memory would lose everything on the restart it is meant to survive, and one
that wrote its own totals to disk would be a second source of truth to
reconcile.

So: sample, label, hand over. `sampled_at` is included because a consumer
detecting a reset needs to know whether two readings are minutes or days
apart.
"""

import asyncio
import hashlib
import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime

from nebula_agent.drivers._exec import run_fixed_argv

_LOGGER = logging.getLogger(__name__)


class UsageSourceUnavailable(Exception):
    """A source could not be read at all.

    Raised rather than returning no samples, because the two are not the same
    thing and the caller reports them differently. An engine that is down and
    an engine with nothing to report both yield zero samples, and quietly
    conflating them means a poll where two of three sources are broken still
    reads as "all sources read, nobody used any traffic" -- which is exactly
    how a stalled counter goes unnoticed for a week.

    The poll still survives one bad source: the route gathers each separately
    and names the ones that failed.
    """


@dataclass(frozen=True, slots=True)
class UsageSample:
    """One credential's counters, as the serving process currently reports them.

    `identity` is a SHA-256 digest, never the raw value. For VLESS and
    Hysteria2 the identity the serving process reports *is* the credential --
    the same UUID the control plane stores encrypted -- so reporting it in the
    clear would hand a second plaintext copy to anything downstream, and the
    control plane would then have to store it. The digest is stable, which is
    all attribution needs.
    """

    protocol: str
    identity: str
    # Named from the server's point of view, matching every source: `rx` is
    # what the server received from the client, `tx` what it sent.
    rx_bytes: int
    tx_bytes: int
    sampled_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


def digest_identity(identity: str) -> str:
    """Hash before reporting. See UsageSample.identity for why.

    The control plane hashes the same way when it resolves a credential back
    to a user, so the two must stay in step -- which is why this is one named
    function rather than an inline call at each source.
    """

    return hashlib.sha256(identity.encode()).hexdigest()


def _fetch_json(url: str, secret: str, timeout_seconds: float) -> object:
    """One blocking GET, so the caller can run it off the event loop.

    stdlib rather than a client library, matching alerting.py and
    reachability.py: the agent runs on the VPN host and every dependency it
    takes is another thing to keep patched there.

    A named module-level function rather than a closure so a test can replace
    it, which is the only seam this module needs.
    """

    request = urllib.request.Request(  # noqa: S310 - fixed http:// loopback URL
        url, headers={"Authorization": secret}
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
        parsed: object = json.loads(response.read().decode())
    return parsed


async def collect_wireguard_usage(
    *, wg_binary: str, interface: str, timeout_seconds: float = 10
) -> list[UsageSample]:
    """Parse `wg show <interface> dump`.

    The dump's first line describes the interface itself and carries no peer,
    so it is skipped. Peer lines are tab separated:

        public-key  preshared-key  endpoint  allowed-ips  handshake  rx  tx  keepalive
    """

    result = await run_fixed_argv(
        [wg_binary, "show", interface, "dump"], timeout_seconds=timeout_seconds
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()[:200]
        _LOGGER.warning("wg show failed for %s: %s", interface, detail)
        raise UsageSourceUnavailable(f"wg show failed for {interface}: {detail}")

    sampled_at = _now()
    samples: list[UsageSample] = []
    for line in result.stdout.decode(errors="replace").splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 7:
            continue
        try:
            rx, tx = int(fields[5]), int(fields[6])
        except ValueError:
            continue
        samples.append(
            UsageSample(
                protocol="wireguard",
                identity=digest_identity(fields[0]),
                rx_bytes=rx,
                tx_bytes=tx,
                sampled_at=sampled_at,
            )
        )
    return samples


async def collect_xray_usage(
    *, xray_binary: str, api_address: str, timeout_seconds: float = 10
) -> list[UsageSample]:
    """Query Xray's stats service.

    Counter names are `user>>><email>>>traffic>>>uplink|downlink`, and the
    email is the client UUID -- see `xray_config_store`, which sets it for
    exactly this reason.

    Read without `reset`: resetting would make the agent the only holder of
    the delta, and a crash between the read and the control plane accepting it
    would lose that traffic permanently. Leaving the counter running means a
    lost sample costs nothing -- the next one still carries the total.
    """

    result = await run_fixed_argv(
        [xray_binary, "api", "statsquery", f"--server={api_address}"],
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()[:200]
        _LOGGER.warning("xray statsquery failed: %s", detail)
        raise UsageSourceUnavailable(f"xray statsquery failed: {detail}")

    try:
        rows = json.loads(result.stdout.decode(errors="replace") or "{}").get("stat", [])
    except json.JSONDecodeError as error:
        _LOGGER.warning("xray statsquery returned unparseable output")
        raise UsageSourceUnavailable("xray statsquery returned unparseable output") from error

    sampled_at = _now()
    totals: dict[str, dict[str, int]] = {}
    for row in rows:
        name = row.get("name", "")
        parts = name.split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        identity, direction = parts[1], parts[3]
        value = int(row.get("value", 0) or 0)
        entry = totals.setdefault(identity, {"uplink": 0, "downlink": 0})
        if direction in entry:
            entry[direction] = value

    return [
        UsageSample(
            protocol="xray",
            identity=_counter_identity(identity),
            # Xray's uplink is client -> server, which is the server
            # receiving. Getting this backwards would silently swap every
            # figure the app shows.
            rx_bytes=entry["uplink"],
            tx_bytes=entry["downlink"],
            sampled_at=sampled_at,
        )
        for identity, entry in totals.items()
    ]


_DIGEST = re.compile(r"[0-9a-f]{64}")


def _counter_identity(label: str) -> str:
    """The reported identity for an Xray or Hysteria2 counter label.

    Labels are already the digest -- see xray_config_store.client_email, and
    Hysteria's HTTP auth, which admits clients under it -- and hashing one
    again would attribute every byte to nobody. A label that is still a raw
    UUID, from a config rendered before that change, is digested here as
    before, so the switch loses no attribution.
    """

    if _DIGEST.fullmatch(label):
        return label
    return digest_identity(label)


async def collect_hysteria_usage(
    *, api_url: str, secret: str, timeout_seconds: float = 10
) -> list[UsageSample]:
    """Read Hysteria2's own traffic endpoint.

    Returns `{"<username>": {"tx": int, "rx": int}}`, keyed by the username --
    which the config store renders as the client UUID.

    Hysteria's `tx`/`rx` are named from the *client's* side: `tx` is what the
    client uploaded, so it is what the server received. They are swapped here
    so every sample this module emits means the same thing.
    """

    try:
        payload = await asyncio.to_thread(_fetch_json, api_url, secret, timeout_seconds)
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as error:
        detail = str(error)[:200]
        _LOGGER.warning("hysteria traffic query failed: %s", detail)
        raise UsageSourceUnavailable(f"hysteria traffic query failed: {detail}") from error
    if not isinstance(payload, dict):
        raise UsageSourceUnavailable("hysteria traffic endpoint returned a non-mapping payload")

    sampled_at = _now()
    samples: list[UsageSample] = []
    for identity, entry in payload.items():
        if not isinstance(entry, dict):
            continue
        samples.append(
            UsageSample(
                protocol="hysteria2",
                identity=_counter_identity(str(identity)),
                rx_bytes=int(entry.get("tx", 0) or 0),
                tx_bytes=int(entry.get("rx", 0) or 0),
                sampled_at=sampled_at,
            )
        )
    return samples
