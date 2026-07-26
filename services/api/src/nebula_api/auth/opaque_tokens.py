"""Versioned opaque tokens and domain-separated keyed digests."""

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass

TOKEN_RANDOM_BYTES = 32
TOKEN_DIGEST_BYTES = 32
_MINIMUM_HMAC_KEY_BYTES = 32
_MAXIMUM_KEY_VERSION = 2_147_483_647
_ENCODED_RANDOM_CHARACTERS = 43
_TOKEN_PATTERN = re.compile(
    rf"v([1-9][0-9]{{0,9}})\.([A-Za-z0-9_-]{{{_ENCODED_RANDOM_CHARACTERS}}})\Z"
)
_NAMESPACE_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_DIGEST_PREFIX = b"nebula:opaque-token-digest:v1\x00"

RandomBytes = Callable[[int], bytes]
KeyRing = Mapping[int, bytes]


class OpaqueTokenError(ValueError):
    """Raised without reflecting malformed token or key material."""


@dataclass(frozen=True, slots=True, repr=False)
class OpaqueTokenDigest:
    """Persistence-safe keyed digest and the key version that produced it."""

    key_version: int
    value: bytes

    def __post_init__(self) -> None:
        if not _valid_key_version(self.key_version) or len(self.value) != TOKEN_DIGEST_BYTES:
            raise ValueError("opaque token digest is invalid")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key_version={self.key_version}, value=<redacted>)"


def issue_opaque_token(
    key_version: int = 1,
    *,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> str:
    """Create a version-prefixed token containing exactly 256 random bits."""

    if not _valid_key_version(key_version):
        raise ValueError("opaque token key version is invalid")
    random_value = random_bytes(TOKEN_RANDOM_BYTES)
    if type(random_value) is not bytes or len(random_value) != TOKEN_RANDOM_BYTES:
        raise RuntimeError("opaque token random source returned invalid data")
    encoded = base64.urlsafe_b64encode(random_value).rstrip(b"=").decode("ascii")
    return f"v{key_version}.{encoded}"


def digest_opaque_token(
    token: str,
    key_ring: KeyRing,
    *,
    namespace: str,
) -> OpaqueTokenDigest:
    """Validate an opaque token and derive its namespace-bound HMAC-SHA256 digest."""

    key_version = _parse_token(token)
    key = _key_for_version(key_ring, key_version)
    namespace_bytes = _validated_namespace(namespace)
    message = _DIGEST_PREFIX + namespace_bytes + b"\x00" + token.encode("ascii")
    return OpaqueTokenDigest(
        key_version=key_version,
        value=hmac.new(key, message, hashlib.sha256).digest(),
    )


def verify_opaque_token(
    token: str,
    expected: OpaqueTokenDigest,
    key_ring: KeyRing,
    *,
    namespace: str,
) -> bool:
    """Compare a candidate with a stored digest without exposing parse failures."""

    try:
        candidate = digest_opaque_token(token, key_ring, namespace=namespace)
    except (OpaqueTokenError, ValueError):
        return False
    return candidate.key_version == expected.key_version and hmac.compare_digest(
        candidate.value, expected.value
    )


def _parse_token(token: str) -> int:
    if type(token) is not str:
        raise OpaqueTokenError("opaque token is invalid")
    match = _TOKEN_PATTERN.fullmatch(token)
    if match is None:
        raise OpaqueTokenError("opaque token is invalid")
    key_version = int(match.group(1))
    if not _valid_key_version(key_version):
        raise OpaqueTokenError("opaque token is invalid")
    try:
        raw_value = base64.b64decode(
            match.group(2) + "=",
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError):
        raise OpaqueTokenError("opaque token is invalid") from None
    if len(raw_value) != TOKEN_RANDOM_BYTES:
        raise OpaqueTokenError("opaque token is invalid")
    return key_version


def _key_for_version(key_ring: KeyRing, key_version: int) -> bytes:
    try:
        key = key_ring[key_version]
    except (KeyError, TypeError):
        raise OpaqueTokenError("opaque token is invalid") from None
    if type(key) is not bytes or len(key) < _MINIMUM_HMAC_KEY_BYTES:
        raise ValueError("opaque token key ring is invalid")
    return key


def _validated_namespace(namespace: str) -> bytes:
    if type(namespace) is not str or _NAMESPACE_PATTERN.fullmatch(namespace) is None:
        raise ValueError("opaque token namespace is invalid")
    return namespace.encode("ascii")


def _valid_key_version(value: object) -> bool:
    return type(value) is int and 1 <= value <= _MAXIMUM_KEY_VERSION
