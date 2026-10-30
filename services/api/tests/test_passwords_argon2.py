import asyncio

import pytest

from nebula_api.passwords import (
    hash_password,
    hash_password_async,
    password_hash_needs_rehash,
    validate_password,
    verify_password,
    verify_password_or_dummy_async,
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


def test_verifying_a_password_leaves_the_event_loop_free() -> None:
    """Argon2id costs 165 ms and 64 MiB per verification on the production
    host. Called inline from a coroutine, that is 165 ms during which this
    single-event-loop API serves nobody -- every refresh and every connected
    client's access check waits behind one sign-in attempt, which anyone can
    trigger. Asserted against the failure mode: a blocking call leaves the
    ticker below at zero.
    """

    hashed = hash_password("correct-horse-battery-staple")

    async def count_ticks_during_a_verification() -> int:
        ticks = 0

        async def tick() -> None:
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0)

        ticker = asyncio.create_task(tick())
        try:
            assert await verify_password_or_dummy_async(hashed, "not-the-password") is False
        finally:
            ticker.cancel()
        return ticks

    assert asyncio.run(count_ticks_during_a_verification()) > 100


def test_hashing_off_the_loop_still_refuses_a_password_that_is_too_short() -> None:
    """The validation the synchronous path does must not be lost in the move
    to a thread -- the exception has to cross back to the caller."""

    with pytest.raises(ValueError):
        asyncio.run(hash_password_async("short"))
