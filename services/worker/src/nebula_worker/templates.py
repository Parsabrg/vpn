"""Minimal fixed plaintext templates for the closed `email_deliveries` vocabulary."""

from dataclasses import dataclass


class UnknownTemplate(ValueError):
    """Raised for a `template_code` outside the reviewed vocabulary."""


@dataclass(frozen=True, slots=True)
class RenderedEmail:
    subject: str
    body: str


def render(template_code: str, payload: dict[str, str]) -> RenderedEmail:
    if template_code == "account_request_review":
        request_id = payload.get("account_request_id", "")
        return RenderedEmail(
            subject="New Nebula account request pending review",
            body=(f"A new account request is waiting for review.\n\nRequest ID: {request_id}\n"),
        )
    if template_code == "user_activation":
        token = payload.get("token", "")
        expires_at = payload.get("expires_at", "")
        return RenderedEmail(
            subject="Activate your Nebula account",
            body=(
                "Your Nebula account request was approved.\n\n"
                f"Activation code: {token}\n"
                f"This code expires at {expires_at}.\n"
            ),
        )
    if template_code == "password_reset":
        token = payload.get("token", "")
        expires_at = payload.get("expires_at", "")
        return RenderedEmail(
            subject="Reset your Nebula password",
            body=(
                "A password reset was requested for your Nebula account.\n\n"
                f"Reset code: {token}\n"
                f"This code expires at {expires_at}.\n"
                "If you did not request this, no action is needed.\n"
            ),
        )
    if template_code == "request_rejected":
        return RenderedEmail(
            subject="Your Nebula account request was not approved",
            body="Your Nebula account request was reviewed and was not approved.\n",
        )
    raise UnknownTemplate(template_code)
