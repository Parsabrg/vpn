from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from nebula_api.auth.access_tokens import (
    ACCESS_TOKEN_ALGORITHM,
    ACCESS_TOKEN_TYPE,
    AccessTokenError,
    decode_access_token,
    issue_access_token,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
SUBJECT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SESSION_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
TOKEN_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
ISSUER = "https://api.example.test"
AUDIENCE = "nebula-mobile"
DEFAULT_SIGNER = Ed25519PrivateKey.generate()
PUBLIC_KEY = DEFAULT_SIGNER.public_key()
KEY_RING = {"current": PUBLIC_KEY}


def _issue(*, ttl_seconds: int = 900) -> str:
    return issue_access_token(
        subject_id=SUBJECT_ID,
        session_id=SESSION_ID,
        issuer=ISSUER,
        audience=AUDIENCE,
        signer=DEFAULT_SIGNER,
        key_id="current",
        ttl_seconds=ttl_seconds,
        clock=lambda: NOW,
        identifier_factory=lambda: TOKEN_ID,
    )


def _payload(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False})


def _sign(
    payload: dict[str, Any],
    *,
    signer: Ed25519PrivateKey = DEFAULT_SIGNER,
    headers: Mapping[str, str] | None = None,
) -> str:
    effective_headers = headers or {"kid": "current", "typ": ACCESS_TOKEN_TYPE}
    return jwt.encode(
        payload,
        signer,
        algorithm=ACCESS_TOKEN_ALGORITHM,
        headers=dict(effective_headers),
    )


def test_issue_and_decode_strict_minimal_access_token() -> None:
    token = _issue()
    header = jwt.get_unverified_header(token)
    payload = _payload(token)

    assert header == {"alg": "EdDSA", "kid": "current", "typ": "at+jwt"}
    assert set(payload) == {
        "iss",
        "aud",
        "sub",
        "sid",
        "jti",
        "iat",
        "nbf",
        "exp",
        "token_use",
    }
    assert payload["token_use"] == "access"  # noqa: S105 - public claim value

    claims = decode_access_token(
        token,
        issuer=ISSUER,
        audience=AUDIENCE,
        verification_keys=KEY_RING,
        clock=lambda: NOW,
    )
    assert claims.subject_id == SUBJECT_ID
    assert claims.session_id == SESSION_ID
    assert claims.token_id == TOKEN_ID
    assert claims.issued_at == NOW
    assert claims.not_before == NOW
    assert claims.expires_at == NOW + timedelta(seconds=900)


def test_expiration_boundary_is_exclusive() -> None:
    token = _issue(ttl_seconds=60)

    decode_access_token(
        token,
        issuer=ISSUER,
        audience=AUDIENCE,
        verification_keys=KEY_RING,
        clock=lambda: NOW + timedelta(seconds=59),
    )
    with pytest.raises(AccessTokenError, match="access token is invalid"):
        decode_access_token(
            token,
            issuer=ISSUER,
            audience=AUDIENCE,
            verification_keys=KEY_RING,
            clock=lambda: NOW + timedelta(seconds=60),
        )


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "https://attacker.invalid"),
        ("aud", "another-client"),
        ("token_use", "refresh"),
        ("sub", True),
        ("sub", "not-a-uuid"),
        ("sub", str(SUBJECT_ID).upper()),
        ("sid", "not-a-uuid"),
        ("jti", "not-a-uuid"),
        ("iat", True),
        ("nbf", "0"),
        ("exp", 0),
    ],
)
def test_invalid_claim_values_are_rejected(claim: str, value: object) -> None:
    payload = _payload(_issue())
    payload[claim] = value
    token = _sign(payload)

    with pytest.raises(AccessTokenError, match="access token is invalid") as error:
        decode_access_token(
            token,
            issuer=ISSUER,
            audience=AUDIENCE,
            verification_keys=KEY_RING,
            clock=lambda: NOW,
        )

    assert token not in str(error.value)


def test_missing_and_unknown_claims_are_rejected() -> None:
    missing = _payload(_issue())
    missing.pop("sid")
    extra = _payload(_issue())
    extra["role"] = "owner"

    for token in (_sign(missing), _sign(extra)):
        with pytest.raises(AccessTokenError, match="access token is invalid"):
            decode_access_token(
                token,
                issuer=ISSUER,
                audience=AUDIENCE,
                verification_keys=KEY_RING,
                clock=lambda: NOW,
            )


def test_future_and_internally_inconsistent_times_are_rejected() -> None:
    future = _payload(_issue())
    future["nbf"] += 1
    issued_after_nbf = _payload(_issue())
    issued_after_nbf["iat"] += 1
    no_lifetime = _payload(_issue())
    no_lifetime["exp"] = no_lifetime["nbf"]

    for token in (_sign(future), _sign(issued_after_nbf), _sign(no_lifetime)):
        with pytest.raises(AccessTokenError, match="access token is invalid"):
            decode_access_token(
                token,
                issuer=ISSUER,
                audience=AUDIENCE,
                verification_keys=KEY_RING,
                clock=lambda: NOW,
            )


@pytest.mark.parametrize(
    "headers",
    [
        {"kid": "current", "typ": "JWT"},
        {"kid": "unknown", "typ": "at+jwt"},
        {"kid": "current", "typ": "at+jwt", "cty": "json"},
    ],
)
def test_unexpected_headers_are_rejected(headers: Mapping[str, str]) -> None:
    token = _sign(_payload(_issue()), headers=headers)

    with pytest.raises(AccessTokenError, match="access token is invalid"):
        decode_access_token(
            token,
            issuer=ISSUER,
            audience=AUDIENCE,
            verification_keys=KEY_RING,
            clock=lambda: NOW,
        )


def test_algorithm_confusion_and_wrong_signature_are_rejected() -> None:
    payload = _payload(_issue())
    hs256_token = jwt.encode(
        payload,
        b"symmetric-attacker-key-at-least-32-bytes",
        algorithm="HS256",
        headers={"kid": "current", "typ": ACCESS_TOKEN_TYPE},
    )
    wrong_signature = _sign(payload, signer=Ed25519PrivateKey.generate())

    for token in (hs256_token, wrong_signature):
        with pytest.raises(AccessTokenError, match="access token is invalid"):
            decode_access_token(
                token,
                issuer=ISSUER,
                audience=AUDIENCE,
                verification_keys=KEY_RING,
                clock=lambda: NOW,
            )


@pytest.mark.parametrize("token", ["", "not.a.jwt", "x" * 4097])
def test_malformed_tokens_receive_one_generic_error(token: str) -> None:
    with pytest.raises(AccessTokenError, match="access token is invalid") as error:
        decode_access_token(
            token,
            issuer=ISSUER,
            audience=AUDIENCE,
            verification_keys=KEY_RING,
            clock=lambda: NOW,
        )
    if token:
        assert token not in str(error.value)


def test_signing_and_clock_configuration_are_validated() -> None:
    with pytest.raises(ValueError, match="lifetime is invalid"):
        issue_access_token(
            subject_id=SUBJECT_ID,
            session_id=SESSION_ID,
            issuer=ISSUER,
            audience=AUDIENCE,
            signer=DEFAULT_SIGNER,
            key_id="current",
            ttl_seconds=0,
            clock=lambda: NOW,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        issue_access_token(
            subject_id=SUBJECT_ID,
            session_id=SESSION_ID,
            issuer=ISSUER,
            audience=AUDIENCE,
            signer=DEFAULT_SIGNER,
            key_id="current",
            clock=lambda: datetime(2026, 7, 20, 12, 0),
        )


def test_issue_rejects_invalid_key_identity_and_identifier_configuration() -> None:
    common: dict[str, Any] = {
        "subject_id": SUBJECT_ID,
        "session_id": SESSION_ID,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signer": DEFAULT_SIGNER,
        "key_id": "current",
        "clock": lambda: NOW,
    }

    with pytest.raises(ValueError, match="signing key"):
        issue_access_token(**{**common, "signer": cast(Ed25519PrivateKey, object())})
    with pytest.raises(ValueError, match="identity"):
        issue_access_token(**{**common, "subject_id": cast(UUID, "not-a-uuid")})
    with pytest.raises(ValueError, match="key identifier"):
        issue_access_token(**{**common, "key_id": "bad key id"})
    with pytest.raises(RuntimeError, match="identifier source"):
        issue_access_token(
            **common,
            identifier_factory=lambda: cast(UUID, "not-a-uuid"),
        )


@pytest.mark.parametrize(("issuer", "audience"), [("", AUDIENCE), (ISSUER, " audience")])
def test_issue_rejects_noncanonical_issuer_and_audience(issuer: str, audience: str) -> None:
    with pytest.raises(ValueError, match="issuer or audience"):
        issue_access_token(
            subject_id=SUBJECT_ID,
            session_id=SESSION_ID,
            issuer=issuer,
            audience=audience,
            signer=DEFAULT_SIGNER,
            key_id="current",
            clock=lambda: NOW,
        )


def test_noncanonical_key_identifier_in_header_is_rejected() -> None:
    token = _sign(
        _payload(_issue()),
        headers={"kid": "bad key id", "typ": ACCESS_TOKEN_TYPE},
    )

    with pytest.raises(AccessTokenError, match="access token is invalid"):
        decode_access_token(
            token,
            issuer=ISSUER,
            audience=AUDIENCE,
            verification_keys=KEY_RING,
            clock=lambda: NOW,
        )


def test_invalid_verification_key_entry_is_rejected_generically() -> None:
    invalid_ring = cast(dict[str, Ed25519PublicKey], {"current": "not-a-key"})

    with pytest.raises(AccessTokenError, match="access token is invalid"):
        decode_access_token(
            _issue(),
            issuer=ISSUER,
            audience=AUDIENCE,
            verification_keys=invalid_ring,
            clock=lambda: NOW,
        )
