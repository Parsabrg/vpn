"""Deterministic identity canonicalization shared by commands and services."""

import re
import unicodedata

from email_validator import EmailNotValidError, validate_email

_USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{1,30}[a-z0-9]\Z")


def normalize_email(value: str) -> str:
    """Validate and canonicalize an email without provider-specific rewriting."""

    candidate = unicodedata.normalize("NFC", value).strip()
    try:
        validated = validate_email(candidate, check_deliverability=False)
    except EmailNotValidError as error:
        raise ValueError("email address is invalid") from error
    return validated.normalized.casefold()


def normalize_username(value: str) -> str:
    """Return the lowercase ASCII identity key for a user-visible username."""

    candidate = unicodedata.normalize("NFKC", value).strip().casefold()
    if not candidate.isascii() or _USERNAME_PATTERN.fullmatch(candidate) is None:
        raise ValueError(
            "username must be 3-32 ASCII letters, digits, dots, underscores, or hyphens"
        )
    return candidate
