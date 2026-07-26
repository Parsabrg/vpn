"""Strict Ed25519 access-token issuance and validation."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ACCESS_TOKEN_TYPE = "at+jwt"  # noqa: S105 - public JOSE media type, not a credential
ACCESS_TOKEN_USE = "access"  # noqa: S105 - public claim discriminator
ACCESS_TOKEN_ALGORITHM = "EdDSA"  # noqa: S105 - public algorithm identifier
DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 900
_MAXIMUM_ACCESS_TOKEN_TTL_SECONDS = 86_400
_MAXIMUM_ENCODED_TOKEN_CHARACTERS = 4_096
_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_REQUIRED_CLAIMS = frozenset({"iss", "aud", "sub", "sid", "jti", "iat", "nbf", "exp", "token_use"})
_REQUIRED_HEADERS = frozenset({"alg", "kid", "typ"})

Clock = Callable[[], datetime]
IdentifierFactory = Callable[[], UUID]
VerificationKeyRing = Mapping[str, Ed25519PublicKey]


class AccessTokenError(ValueError):
    """Raised with a stable message that does not reveal validation details."""


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """Validated minimal claims used by the user-authentication dependency."""

    issuer: str
    audience: str
    subject_id: UUID
    session_id: UUID
    token_id: UUID
    issued_at: datetime
    not_before: datetime
    expires_at: datetime


def issue_access_token(
    *,
    subject_id: UUID,
    session_id: UUID,
    issuer: str,
    audience: str,
    signer: Ed25519PrivateKey,
    key_id: str,
    ttl_seconds: int = DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
    clock: Clock = lambda: datetime.now(UTC),
    identifier_factory: IdentifierFactory = uuid4,
) -> str:
    """Issue a minimal EdDSA access JWT with fixed type and use claims."""

    _validate_issuer_and_audience(issuer, audience)
    _validate_key_id(key_id)
    if not isinstance(signer, Ed25519PrivateKey):
        raise ValueError("access token signing key is invalid")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= _MAXIMUM_ACCESS_TOKEN_TTL_SECONDS:
        raise ValueError("access token lifetime is invalid")
    if not isinstance(subject_id, UUID) or not isinstance(session_id, UUID):
        raise ValueError("access token identity is invalid")

    issued_at = _aware_utc(clock())
    issued_epoch = int(issued_at.timestamp())
    token_id = identifier_factory()
    if not isinstance(token_id, UUID):
        raise RuntimeError("access token identifier source returned invalid data")

    payload: dict[str, str | int] = {
        "iss": issuer,
        "aud": audience,
        "sub": str(subject_id),
        "sid": str(session_id),
        "jti": str(token_id),
        "iat": issued_epoch,
        "nbf": issued_epoch,
        "exp": issued_epoch + ttl_seconds,
        "token_use": ACCESS_TOKEN_USE,
    }
    return jwt.encode(
        payload,
        signer,
        algorithm=ACCESS_TOKEN_ALGORITHM,
        headers={"kid": key_id, "typ": ACCESS_TOKEN_TYPE},
    )


def decode_access_token(
    token: str,
    *,
    issuer: str,
    audience: str,
    verification_keys: VerificationKeyRing,
    clock: Clock = lambda: datetime.now(UTC),
) -> AccessTokenClaims:
    """Verify a strict access JWT and return typed claims or one generic error."""

    _validate_issuer_and_audience(issuer, audience)
    if type(token) is not str or not token or len(token) > _MAXIMUM_ENCODED_TOKEN_CHARACTERS:
        raise AccessTokenError("access token is invalid")

    try:
        header = jwt.get_unverified_header(token)
        if set(header) != _REQUIRED_HEADERS:
            raise AccessTokenError("access token is invalid")
        if header.get("alg") != ACCESS_TOKEN_ALGORITHM or header.get("typ") != ACCESS_TOKEN_TYPE:
            raise AccessTokenError("access token is invalid")
        key_id = header.get("kid")
        if type(key_id) is not str or _KEY_ID_PATTERN.fullmatch(key_id) is None:
            raise AccessTokenError("access token is invalid")
        verification_key = verification_keys[key_id]
        if not isinstance(verification_key, Ed25519PublicKey):
            raise AccessTokenError("access token is invalid")

        payload: dict[str, Any] = jwt.decode(
            token,
            verification_key,
            algorithms=[ACCESS_TOKEN_ALGORITHM],
            audience=audience,
            issuer=issuer,
            options={
                "require": sorted(_REQUIRED_CLAIMS),
                "strict_aud": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        return _validated_claims(payload, issuer=issuer, audience=audience, clock=clock)
    except AccessTokenError:
        raise
    except (KeyError, TypeError, ValueError, jwt.PyJWTError):
        raise AccessTokenError("access token is invalid") from None


def _validated_claims(
    payload: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    clock: Clock,
) -> AccessTokenClaims:
    if set(payload) != _REQUIRED_CLAIMS:
        raise AccessTokenError("access token is invalid")
    if (
        type(payload["iss"]) is not str
        or payload["iss"] != issuer
        or type(payload["aud"]) is not str
        or payload["aud"] != audience
        or type(payload["token_use"]) is not str
        or payload["token_use"] != ACCESS_TOKEN_USE
    ):
        raise AccessTokenError("access token is invalid")

    subject_id = _canonical_uuid(payload["sub"])
    session_id = _canonical_uuid(payload["sid"])
    token_id = _canonical_uuid(payload["jti"])
    issued_epoch = _numeric_date(payload["iat"])
    not_before_epoch = _numeric_date(payload["nbf"])
    expires_epoch = _numeric_date(payload["exp"])
    now_epoch = int(_aware_utc(clock()).timestamp())

    if (
        issued_epoch > not_before_epoch
        or not_before_epoch > now_epoch
        or expires_epoch <= now_epoch
        or expires_epoch <= not_before_epoch
    ):
        raise AccessTokenError("access token is invalid")

    return AccessTokenClaims(
        issuer=issuer,
        audience=audience,
        subject_id=subject_id,
        session_id=session_id,
        token_id=token_id,
        issued_at=datetime.fromtimestamp(issued_epoch, UTC),
        not_before=datetime.fromtimestamp(not_before_epoch, UTC),
        expires_at=datetime.fromtimestamp(expires_epoch, UTC),
    )


def _canonical_uuid(value: object) -> UUID:
    if type(value) is not str:
        raise AccessTokenError("access token is invalid")
    try:
        parsed = UUID(value)
    except ValueError:
        raise AccessTokenError("access token is invalid") from None
    if str(parsed) != value:
        raise AccessTokenError("access token is invalid")
    return parsed


def _numeric_date(value: object) -> int:
    if type(value) is not int or value < 0:
        raise AccessTokenError("access token is invalid")
    return value


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("authentication clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


def _validate_key_id(key_id: str) -> None:
    if type(key_id) is not str or _KEY_ID_PATTERN.fullmatch(key_id) is None:
        raise ValueError("access token key identifier is invalid")


def _validate_issuer_and_audience(issuer: str, audience: str) -> None:
    for value in (issuer, audience):
        if type(value) is not str or not value or len(value) > 256 or value.strip() != value:
            raise ValueError("access token issuer or audience is invalid")
