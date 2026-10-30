import pytest

from nebula_api.auth.device_identity import hardware_id_matches, hash_hardware_id

KEYS = {1: b"a" * 32, 2: b"b" * 32}


def test_a_hash_matches_its_own_hardware_only() -> None:
    version, digest = hash_hardware_id("phone-1", KEYS, key_version=1)

    assert hardware_id_matches("phone-1", stored_hash=digest, stored_version=version, key_ring=KEYS)
    assert not hardware_id_matches(
        "phone-2", stored_hash=digest, stored_version=version, key_ring=KEYS
    )


def test_an_older_key_still_matches_after_rotation() -> None:
    _, digest = hash_hardware_id("phone-1", KEYS, key_version=1)

    assert hardware_id_matches("phone-1", stored_hash=digest, stored_version=1, key_ring=KEYS)
    assert not hardware_id_matches("phone-1", stored_hash=digest, stored_version=2, key_ring=KEYS)


def test_a_retired_key_matches_nothing() -> None:
    _, digest = hash_hardware_id("phone-1", KEYS, key_version=1)

    assert not hardware_id_matches(
        "phone-1", stored_hash=digest, stored_version=1, key_ring={2: KEYS[2]}
    )


def test_hashing_needs_the_configured_key() -> None:
    with pytest.raises(KeyError):
        hash_hardware_id("phone-1", KEYS, key_version=3)
