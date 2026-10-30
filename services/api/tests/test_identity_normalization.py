import pytest

from nebula_api.identity import normalize_email, normalize_username


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (" User@EXAMPLE.COM ", "user@example.com"),
        ("person@B\u00dcCHER.example", "person@b\u00fccher.example"),
    ],
)
def test_email_normalization_is_deterministic(value: str, expected: str) -> None:
    assert normalize_email(value) == expected


@pytest.mark.parametrize("value", ["", "missing-at.example", "a@", "a@example..com"])
def test_invalid_email_is_rejected_without_echoing_input(value: str) -> None:
    with pytest.raises(ValueError, match="email address is invalid") as error:
        normalize_email(value)

    if value:
        assert value not in str(error.value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(" Alice-01 ", "alice-01"), ("\uff21bc", "abc"), ("a.b_c", "a.b_c")],
)
def test_username_normalization_returns_ascii_canonical_form(value: str, expected: str) -> None:
    assert normalize_username(value) == expected


@pytest.mark.parametrize("value", ["a", "ab", ".alice", "alice.", "\u00e1l\u00eece", "a space"])
def test_noncanonical_username_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="ASCII"):
        normalize_username(value)
