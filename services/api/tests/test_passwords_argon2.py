import pytest

from nebula_api.passwords import (
    hash_password,
    password_hash_needs_rehash,
    validate_password,
    verify_password,
)


def test_argon2id_hash_round_trip_and_safe_mismatch() -> None:
    seed_input = "a-long-seed-password"
    encoded = hash_password(seed_input)

    assert encoded.startswith("$argon2id$")
    assert seed_input not in encoded
    assert verify_password(encoded, seed_input) is True
    assert verify_password(encoded, "not-the-password") is False
    assert password_hash_needs_rehash(encoded) is False


def test_malformed_password_hash_is_handled_as_nonmatch() -> None:
    assert verify_password("not-an-argon2-hash", "candidate-password") is False
    assert password_hash_needs_rehash("not-an-argon2-hash") is True


@pytest.mark.parametrize("password", ["short", "\u00e9" * 513])
def test_password_size_bounds(password: str) -> None:
    with pytest.raises(ValueError):
        validate_password(password)
