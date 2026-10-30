from uuid import UUID

from nebula_agent.drivers.egress import BLOCKED_DESTINATIONS
from nebula_agent.drivers.hysteria_config_store import (
    HysteriaServerProfile,
    render_hysteria_server_config,
)

PROFILE = HysteriaServerProfile(
    protocol_profile_code="hysteria2",
    port=8450,
    tls_cert_file="/etc/letsencrypt/live/example.test/fullchain.pem",
    tls_key_file="/etc/letsencrypt/live/example.test/privkey.pem",
    obfs_password="s3cret-salamander",  # noqa: S106 - test fixture, not real
    up_mbps=100,
    down_mbps=100,
    masquerade_url="https://news.ycombinator.com",
)

CLIENT_A = UUID("11111111-1111-1111-1111-111111111111")
CLIENT_B = UUID("22222222-2222-2222-2222-222222222222")


def test_each_client_becomes_one_userpass_entry() -> None:
    rendered = render_hysteria_server_config((CLIENT_A, CLIENT_B), PROFILE)
    assert '"11111111-1111-1111-1111-111111111111": "11111111-1111-1111-1111-111111111111"' in (
        rendered
    )
    assert '"22222222-2222-2222-2222-222222222222"' in rendered
    assert "type: userpass" in rendered


def test_an_empty_client_set_still_renders_a_startable_config() -> None:
    """Hysteria refuses both a bare `userpass:` (parses as null) and an empty
    map -- "invalid config: auth.userpass: empty auth userpass".

    The empty map was shipped on the reasoning that it authenticates nobody.
    It does, by crash-looping the service: 25,000 restarts deep before anyone
    noticed, with the transport down for everyone from the moment the last
    client was revoked. Asserted here against the failure mode rather than the
    reasoning.
    """

    rendered = render_hysteria_server_config((), PROFILE)
    assert "    {}" not in rendered
    assert "__no_clients__" in rendered


def test_the_zero_client_placeholder_is_stable_across_renders() -> None:
    """An entry that differed per render would restart the service on every
    apply, which is what the skip-if-unchanged check exists to avoid."""

    assert render_hysteria_server_config((), PROFILE) == render_hysteria_server_config((), PROFILE)


def test_the_zero_client_placeholder_is_not_a_usable_credential() -> None:
    """It is derived from the obfuscation password, so guessing it requires
    already holding the secret needed to reach this server at all."""

    rendered = render_hysteria_server_config((), PROFILE)
    placeholder_line = next(line for line in rendered.splitlines() if "__no_clients__" in line)
    assert PROFILE.obfs_password not in placeholder_line


def test_rendering_is_deterministic_regardless_of_client_order() -> None:
    """An unchanged client set must produce an identical file, so that a diff
    means something actually changed."""

    assert render_hysteria_server_config((CLIENT_A, CLIENT_B), PROFILE) == (
        render_hysteria_server_config((CLIENT_B, CLIENT_A), PROFILE)
    )


def test_obfuscation_is_always_rendered() -> None:
    """Plain unobfuscated QUIC is silently dropped by the ISP this deployment
    exists to serve, so a config without it is a config that does not work."""

    rendered = render_hysteria_server_config((CLIENT_A,), PROFILE)
    assert "type: salamander" in rendered
    assert 'password: "s3cret-salamander"' in rendered


def test_bandwidth_is_advisory_and_bbr_is_in_charge() -> None:
    """Hysteria2's default Brutal sender transmits at whatever the client
    declares, which on a real link overshoots continuously -- observed live as
    unusable jitter until this was set."""

    rendered = render_hysteria_server_config((CLIENT_A,), PROFILE)
    assert "ignoreClientBandwidth: true" in rendered


def test_masquerade_gives_a_prober_a_real_site() -> None:
    rendered = render_hysteria_server_config((CLIENT_A,), PROFILE)
    assert "type: proxy" in rendered
    assert 'url: "https://news.ycombinator.com"' in rendered
    assert "rewriteHost: true" in rendered


def test_values_needing_escapes_do_not_break_the_document() -> None:
    profile = HysteriaServerProfile(
        protocol_profile_code="hysteria2",
        port=8450,
        tls_cert_file="/etc/ssl/a b/full.pem",
        tls_key_file="/etc/ssl/a b/key.pem",
        obfs_password='has"quote\\and-backslash',  # noqa: S106 - test fixture, not real
        up_mbps=1,
        down_mbps=1,
        masquerade_url="https://example.test/?a=1&b=2",
    )
    rendered = render_hysteria_server_config((CLIENT_A,), profile)
    assert 'password: "has\\"quote\\\\and-backslash"' in rendered


def test_the_served_config_refuses_to_dial_this_host_for_a_client() -> None:
    """Hysteria2 dials on the client's behalf from the VPN host, and it does
    so as root, so without these rules a client could address this machine's
    own loopback, the Docker networks PostgreSQL and Redis sit on, the
    WireGuard subnet other users are on, and the cloud metadata service."""

    rendered = render_hysteria_server_config((CLIENT_A,), PROFILE)

    for destination in ("127.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16", "10.0.0.0/8", "::1/128"):
        assert f"    - reject({destination})" in rendered
    lines = [line for line in rendered.splitlines() if line.startswith("    - ")]
    # Last, so every reject above is reached first.
    assert lines[-1] == "    - direct(all)"
    assert "acl:" in rendered


def test_the_blocked_ranges_are_the_ones_the_other_transport_refuses() -> None:
    """One policy, rendered into two config formats -- a range added for Xray
    and forgotten here would leave the same hole open on this transport."""

    rendered = render_hysteria_server_config((CLIENT_A,), PROFILE)

    for destination in BLOCKED_DESTINATIONS:
        assert f"    - reject({destination})" in rendered
