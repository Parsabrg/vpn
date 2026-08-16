import os
from ipaddress import ip_address
from pathlib import Path, PurePosixPath

import pytest

from nebula_agent.drivers.config_store import (
    ConfigStore,
    DesiredInterfaceState,
    RenderedPeer,
    parse_wireguard_config,
    render_wireguard_config,
)

PEER_A = RenderedPeer(
    public_key="peer-a-key",
    assigned_address=ip_address("10.77.0.2"),
    persistent_keepalive_seconds=25,
)
PEER_B = RenderedPeer(public_key="peer-b-key", assigned_address=ip_address("10.77.0.3"))


def test_with_peer_adds_a_new_peer() -> None:
    state = DesiredInterfaceState().with_peer(PEER_A)
    assert state.peers == (PEER_A,)


def test_with_peer_replaces_an_existing_peer_by_public_key() -> None:
    updated = RenderedPeer(public_key=PEER_A.public_key, assigned_address=ip_address("10.77.0.9"))
    state = DesiredInterfaceState(peers=(PEER_A,)).with_peer(updated)
    assert state.peers == (updated,)


def test_without_peer_removes_by_public_key() -> None:
    state = DesiredInterfaceState(peers=(PEER_A, PEER_B)).without_peer(PEER_A.public_key)
    assert state.peers == (PEER_B,)


def test_render_and_parse_round_trip() -> None:
    state = DesiredInterfaceState(peers=(PEER_A, PEER_B))
    text = render_wireguard_config(state)
    parsed = parse_wireguard_config(text)
    assert parsed == state


def test_render_uses_a_128_prefix_for_ipv6_addresses() -> None:
    peer = RenderedPeer(public_key="v6-peer", assigned_address=ip_address("fd00::2"))
    text = render_wireguard_config(DesiredInterfaceState(peers=(peer,)))
    assert "AllowedIPs = fd00::2/128" in text


def test_empty_state_renders_and_parses_to_no_peers() -> None:
    assert parse_wireguard_config(render_wireguard_config(DesiredInterfaceState())) == (
        DesiredInterfaceState()
    )


def test_read_last_known_good_is_empty_before_anything_is_promoted(tmp_path: Path) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    assert store.read_last_known_good() == DesiredInterfaceState()


def test_write_and_promote_round_trips_through_read_last_known_good(tmp_path: Path) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    state = DesiredInterfaceState(peers=(PEER_A,))

    text = store.render_candidate(state)
    candidate = store.write_candidate_atomically(text)
    assert candidate.exists()
    assert not store.last_known_good_path.exists()

    store.promote_candidate_to_last_known_good(candidate)
    assert store.last_known_good_path.exists()
    assert not candidate.exists()
    assert store.read_last_known_good() == state


def test_rollback_text_is_empty_config_before_anything_is_promoted(tmp_path: Path) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    assert store.rollback_text() == render_wireguard_config(DesiredInterfaceState())


def test_rollback_text_matches_the_last_promoted_state(tmp_path: Path) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    state = DesiredInterfaceState(peers=(PEER_A, PEER_B))
    candidate = store.write_candidate_atomically(store.render_candidate(state))
    store.promote_candidate_to_last_known_good(candidate)

    assert parse_wireguard_config(store.rollback_text()) == state


def test_write_candidate_atomically_leaves_no_temp_file_on_success(tmp_path: Path) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    store.write_candidate_atomically("[Peer]\n")

    remaining = {path.name for path in tmp_path.iterdir()}
    assert remaining == {"wg0.conf.candidate"}


def test_write_candidate_atomically_cleans_up_the_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")

    def failing_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError, match="simulated rename failure"):
        store.write_candidate_atomically("[Peer]\n")

    assert list(tmp_path.iterdir()) == []


def test_parse_ignores_unrecognized_lines() -> None:
    text = (
        "[Interface]\n"
        "# a comment\n"
        "ListenPort = 51820\n"
        "\n"
        "[Peer]\n"
        "PublicKey = peer-a-key\n"
        "AllowedIPs = 10.77.0.2/32\n"
    )
    parsed = parse_wireguard_config(text)
    expected = RenderedPeer(public_key="peer-a-key", assigned_address=ip_address("10.77.0.2"))
    assert parsed.peers == (expected,)
