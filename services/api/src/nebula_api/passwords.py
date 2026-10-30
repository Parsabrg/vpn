"""Argon2id password hashing primitives for interactive administrator seeding."""

import asyncio
import secrets
from concurrent.futures import ThreadPoolExecutor

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type

_MINIMUM_CHARACTERS = 12
MAXIMUM_PASSWORD_UTF8_BYTES = 1_024

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash(secrets.token_urlsafe(48))


def validate_password(password: str) -> None:
    """Reject empty, trivially short, or unreasonably large seed passwords."""

    if len(password) < _MINIMUM_CHARACTERS:
        raise ValueError(f"password must contain at least {_MINIMUM_CHARACTERS} characters")
    if len(password.encode("utf-8")) > MAXIMUM_PASSWORD_UTF8_BYTES:
        raise ValueError("password is too large")


def hash_password(password: str) -> str:
    """Validate and hash a password with the fixed Argon2id baseline."""

    validate_password(password)
    return _PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, candidate: str) -> bool:
    """Verify a candidate without exposing malformed-hash or mismatch details."""

    try:
        return _PASSWORD_HASHER.verify(password_hash, candidate)
    except (InvalidHashError, VerificationError):
        return False


def verify_password_or_dummy(password_hash: str | None, candidate: str) -> bool:
    """Perform fixed-cost verification even when an identity has no usable hash."""

    return verify_password(password_hash or _DUMMY_PASSWORD_HASH, candidate)


def password_hash_needs_rehash(password_hash: str) -> bool:
    """Return whether a valid encoded hash predates the current cost baseline.

    Cheap, unlike the two above: it reads the parameters out of the encoded
    hash and compares them. No key derivation happens, so this one is safe to
    call straight from a coroutine.
    """

    try:
        return _PASSWORD_HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


# One Argon2id verification costs 165 ms and 64 MiB on the production host,
# measured in its own container. Run from a coroutine that is what it costs
# *the whole process*: this API is a single event loop, so every other
# request in flight -- other people's refreshes, the access check each
# connected client runs every thirty seconds -- waits behind it, and a burst
# of sign-ins is enough to stall the service for everyone. That is a cheap
# denial of service against an endpoint anybody can reach.
#
# So hashing happens on threads. argon2-cffi releases the GIL while it works,
# which is what makes that real concurrency rather than a rename.
#
# The pool is small on purpose, and it is the memory that sets the size:
# every hash in flight holds 64 MiB, against a container limited to 1 GiB
# (infrastructure/compose/production.yaml). Four is 256 MiB at full tilt.
# Callers beyond that wait for a thread, which is the same backpressure the
# old inline call had, except the event loop is free meanwhile.
_MAXIMUM_CONCURRENT_HASHES = 4
_HASHING_POOL = ThreadPoolExecutor(
    max_workers=_MAXIMUM_CONCURRENT_HASHES, thread_name_prefix="argon2"
)


async def hash_password_async(password: str) -> str:
    """Hash without blocking the event loop. See `_HASHING_POOL`."""

    return await asyncio.get_running_loop().run_in_executor(_HASHING_POOL, hash_password, password)


async def verify_password_or_dummy_async(password_hash: str | None, candidate: str) -> bool:
    """Verify without blocking the event loop. See `_HASHING_POOL`."""

    return await asyncio.get_running_loop().run_in_executor(
        _HASHING_POOL, verify_password_or_dummy, password_hash, candidate
    )
