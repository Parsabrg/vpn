"""Argon2id password hashing primitives for interactive administrator seeding."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type

_MINIMUM_CHARACTERS = 12
_MAXIMUM_UTF8_BYTES = 1024

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def validate_password(password: str) -> None:
    """Reject empty, trivially short, or unreasonably large seed passwords."""

    if len(password) < _MINIMUM_CHARACTERS:
        raise ValueError(f"password must contain at least {_MINIMUM_CHARACTERS} characters")
    if len(password.encode("utf-8")) > _MAXIMUM_UTF8_BYTES:
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


def password_hash_needs_rehash(password_hash: str) -> bool:
    """Return whether a valid encoded hash predates the current cost baseline."""

    try:
        return _PASSWORD_HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
