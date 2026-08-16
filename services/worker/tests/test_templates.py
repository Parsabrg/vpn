import pytest

from nebula_worker.templates import UnknownTemplate, render


def test_account_request_review_includes_request_id() -> None:
    rendered = render("account_request_review", {"account_request_id": "canary-id"})

    assert "canary-id" in rendered.body
    assert "review" in rendered.subject.lower()


def test_user_activation_includes_token_and_expiry() -> None:
    rendered = render(
        "user_activation", {"token": "v1.activation-canary", "expires_at": "2026-08-01T00:00:00Z"}
    )

    assert "v1.activation-canary" in rendered.body
    assert "2026-08-01T00:00:00Z" in rendered.body


def test_password_reset_includes_token_and_expiry() -> None:
    rendered = render(
        "password_reset", {"token": "v1.reset-canary", "expires_at": "2026-08-01T00:00:00Z"}
    )

    assert "v1.reset-canary" in rendered.body


def test_request_rejected_needs_no_payload() -> None:
    rendered = render("request_rejected", {})

    assert "not approved" in rendered.body


def test_unknown_template_code_is_rejected() -> None:
    with pytest.raises(UnknownTemplate):
        render("something_else", {})
