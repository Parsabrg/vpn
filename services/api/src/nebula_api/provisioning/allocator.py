"""Pure WireGuard client-address allocation: no DB, no network.

Concurrency safety (a Postgres advisory transaction lock per server, taken
before calling this) and the exclusion set (every address ever used at the
server -- see the module docstring in provisioning/service.py for why
`wireguard_peers`' address-uniqueness constraint is unconditional, not just
"currently live") are the caller's responsibility.
"""

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


def allocate_next_address(
    *,
    pool: IPNetwork,
    gateway_address: IPAddress | None,
    excluded_addresses: Iterable[IPAddress],
) -> IPAddress | None:
    """The first free host address in `pool`, skipping the network/broadcast
    addresses (`pool.hosts()` already excludes these), `gateway_address`, and
    everything in `excluded_addresses`. Returns None if the pool is
    exhausted."""

    excluded = set(excluded_addresses)
    if gateway_address is not None:
        excluded.add(gateway_address)
    for candidate in pool.hosts():
        if candidate not in excluded:
            return candidate
    return None
