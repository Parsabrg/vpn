from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from hypothesis import given
from hypothesis import strategies as st

from nebula_api.provisioning.allocator import allocate_next_address


def test_allocates_the_first_host_address_in_an_empty_pool() -> None:
    pool = IPv4Network("10.77.0.0/24")
    result = allocate_next_address(pool=pool, gateway_address=None, excluded_addresses=())
    assert result == ip_address("10.77.0.1")


def test_skips_the_gateway_address() -> None:
    pool = IPv4Network("10.77.0.0/24")
    gateway = ip_address("10.77.0.1")
    result = allocate_next_address(pool=pool, gateway_address=gateway, excluded_addresses=())
    assert result == ip_address("10.77.0.2")


def test_skips_already_excluded_addresses_leaving_gaps() -> None:
    pool = IPv4Network("10.77.0.0/29")  # hosts: .1-.6
    excluded = {ip_address("10.77.0.1"), ip_address("10.77.0.2"), ip_address("10.77.0.4")}
    result = allocate_next_address(pool=pool, gateway_address=None, excluded_addresses=excluded)
    assert result == ip_address("10.77.0.3")


def test_returns_none_when_the_pool_is_exhausted() -> None:
    pool = IPv4Network("10.77.0.0/30")  # hosts: .1, .2
    excluded = {ip_address("10.77.0.1"), ip_address("10.77.0.2")}
    result = allocate_next_address(pool=pool, gateway_address=None, excluded_addresses=excluded)
    assert result is None


def test_gateway_and_exclusions_together_exhaust_a_small_pool() -> None:
    pool = IPv4Network("10.77.0.0/30")  # hosts: .1, .2
    result = allocate_next_address(
        pool=pool,
        gateway_address=ip_address("10.77.0.1"),
        excluded_addresses={ip_address("10.77.0.2")},
    )
    assert result is None


def test_works_for_ipv6_pools() -> None:
    pool = IPv6Network("fd00::/126")  # hosts: fd00::1, fd00::2
    result = allocate_next_address(
        pool=pool, gateway_address=None, excluded_addresses={ip_address("fd00::1")}
    )
    assert result == ip_address("fd00::2")


@st.composite
def _small_ipv4_pools(draw: st.DrawFn) -> IPv4Network:
    prefix = draw(st.integers(min_value=24, max_value=29))
    base = draw(st.integers(min_value=0, max_value=(1 << 32) - 1))
    network = ip_network((base, prefix), strict=False)
    assert isinstance(network, IPv4Network)
    return network


@given(pool=_small_ipv4_pools(), excluded_indices=st.sets(st.integers(min_value=0, max_value=6)))
def test_result_is_always_a_valid_unexcluded_host_or_none(
    pool: IPv4Network, excluded_indices: set[int]
) -> None:
    hosts = list(pool.hosts())
    excluded = {hosts[i] for i in excluded_indices if i < len(hosts)}

    result = allocate_next_address(pool=pool, gateway_address=None, excluded_addresses=excluded)

    if result is None:
        assert set(hosts) <= excluded
    else:
        assert result in hosts
        assert result not in excluded
