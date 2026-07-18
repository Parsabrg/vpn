import pytest
from pydantic import ValidationError

from nebula_api.settings import Settings


@pytest.mark.parametrize(
    "url",
    [
        "/relative",
        "https://user:password@api.example.com",
        "https://api.example.com?token=secret",
    ],
)
def test_public_url_rejects_non_public_values(url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(api_public_url=url)


def test_production_requires_https() -> None:
    with pytest.raises(ValidationError, match="production URLs"):
        Settings(
            env="production",
            api_public_url="http://api.example.com",
            allowed_origins="https://admin.example.com",
        )


def test_wildcard_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="exact HTTP"):
        Settings(allowed_origins="*")


@pytest.mark.parametrize("origins", [",", "https://admin.example.com/path"])
def test_invalid_origin_lists_are_rejected(origins: str) -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_origins=origins)


def test_safe_production_urls_are_normalized() -> None:
    settings = Settings(
        env="production",
        api_public_url="https://api.example.com/",
        allowed_origins="https://admin.example.com/, https://support.example.com",
    )

    assert settings.api_public_url == "https://api.example.com"
    assert settings.allowed_origins == ("https://admin.example.com/,https://support.example.com")


def test_unknown_explicit_setting_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Settings(unexpected=True)  # type: ignore[call-arg]
