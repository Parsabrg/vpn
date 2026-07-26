import base64
from collections.abc import Callable
from typing import cast

import pytest

from nebula_api.auth.opaque_tokens import (
    OpaqueTokenDigest,
    OpaqueTokenError,
    digest_opaque_token,
    issue_opaque_token,
    verify_opaque_token,
)

KEY_RING = {1: b"a" * 32, 2: b"b" * 32}


def test_issue_opaque_token_uses_32_bytes_and_unpadded_base64url() -> None:
    token = issue_opaque_token(random_bytes=lambda size: bytes(range(size)))

    version, encoded = token.split(".")
    assert version == "v1"
    assert len(encoded) == 43
    assert "=" not in encoded
    assert base64.urlsafe_b64decode(encoded + "=") == bytes(range(32))


def test_versioned_digest_is_deterministic_namespaced_and_verifiable() -> None:
    token = issue_opaque_token(2, random_bytes=lambda size: b"x" * size)

    digest = digest_opaque_token(token, KEY_RING, namespace="refresh")
    other_namespace = digest_opaque_token(token, KEY_RING, namespace="password-reset")

    assert digest.key_version == 2
    assert len(digest.value) == 32
    assert digest != other_namespace
    assert verify_opaque_token(token, digest, KEY_RING, namespace="refresh")
    assert not verify_opaque_token(token, digest, KEY_RING, namespace="password-reset")
    assert "x" * 20 not in repr(digest)
    assert "<redacted>" in repr(digest)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-token",
        "v0." + "A" * 43,
        "v01." + "A" * 43,
        "v2147483648." + "A" * 43,
        "v1." + "A" * 42,
        "v1." + "A" * 44,
        "v1." + "A" * 42 + "=",
        "v1." + "A" * 42 + "+",
        "v1." + "A" * 42 + "/",
        "v1." + "A" * 43 + ".extra",
        " v1." + "A" * 43,
    ],
)
def test_malformed_tokens_are_rejected_without_echo(token: str) -> None:
    with pytest.raises(OpaqueTokenError, match="opaque token is invalid") as error:
        digest_opaque_token(token, KEY_RING, namespace="refresh")

    if token:
        assert token not in str(error.value)


def test_unknown_key_version_is_rejected_and_verification_is_neutral() -> None:
    token = issue_opaque_token(2, random_bytes=lambda size: b"z" * size)
    expected = OpaqueTokenDigest(key_version=2, value=b"d" * 32)

    with pytest.raises(OpaqueTokenError, match="opaque token is invalid"):
        digest_opaque_token(token, {1: b"a" * 32}, namespace="refresh")

    assert not verify_opaque_token(token, expected, {1: b"a" * 32}, namespace="refresh")


@pytest.mark.parametrize(
    "random_source",
    [lambda _size: b"short", lambda _size: "not-bytes"],
)
def test_random_source_must_return_exactly_32_bytes(
    random_source: Callable[[int], object],
) -> None:
    with pytest.raises(RuntimeError, match="random source returned invalid data"):
        issue_opaque_token(random_bytes=random_source)  # type: ignore[arg-type]


def test_invalid_key_ring_and_namespace_are_rejected() -> None:
    token = issue_opaque_token(random_bytes=lambda size: b"q" * size)

    with pytest.raises(ValueError, match="key ring is invalid"):
        digest_opaque_token(token, {1: b"short"}, namespace="refresh")
    with pytest.raises(ValueError, match="namespace is invalid"):
        digest_opaque_token(token, KEY_RING, namespace="Bad Namespace")


def test_wrong_well_formed_token_does_not_verify() -> None:
    first = issue_opaque_token(random_bytes=lambda size: b"1" * size)
    second = issue_opaque_token(random_bytes=lambda size: b"2" * size)
    expected = digest_opaque_token(first, KEY_RING, namespace="refresh")

    assert not verify_opaque_token(second, expected, KEY_RING, namespace="refresh")


def test_digest_and_issue_reject_invalid_typed_boundaries() -> None:
    with pytest.raises(ValueError, match="digest is invalid"):
        OpaqueTokenDigest(key_version=0, value=b"x" * 32)
    with pytest.raises(ValueError, match="digest is invalid"):
        OpaqueTokenDigest(key_version=1, value=b"short")
    with pytest.raises(ValueError, match="key version is invalid"):
        issue_opaque_token(0)

    with pytest.raises(OpaqueTokenError, match="opaque token is invalid"):
        digest_opaque_token(cast(str, 42), KEY_RING, namespace="refresh")

    token = issue_opaque_token(random_bytes=lambda size: b"q" * size)
    with pytest.raises(OpaqueTokenError, match="opaque token is invalid"):
        digest_opaque_token(token, cast(dict[int, bytes], None), namespace="refresh")
    with pytest.raises(ValueError, match="namespace is invalid"):
        digest_opaque_token(token, KEY_RING, namespace=cast(str, 42))
