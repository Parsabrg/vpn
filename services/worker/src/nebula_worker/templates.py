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
        # Absent from payloads staged before the API sent it.
        review_url = payload.get("review_url", "")
        review = f"Review it in the admin panel:\n  {review_url}\n\n" if review_url else ""
        return RenderedEmail(
            subject="New Nebula account request pending review",
            body=(
                "A new account request is waiting for review.\n\n"
                f"{review}Request ID: {request_id}\n"
            ),
        )
    if template_code == "user_activation":
        token = payload.get("token", "")
        expires_at = payload.get("expires_at", "")
        username = payload.get("username", "")
        email = payload.get("email", "")
        # Names the account, then gives one instruction per screen the reader
        # actually sees. The earlier version sent only the code, leaving two
        # real questions unanswered: which account this is for, and what to do
        # with a code when the app only asks for a password. The quoted labels
        # below match the app's own exactly, so they can be followed literally.
        identifiers = f"  Email:    {email}\n"
        if username:
            identifiers += f"  Username: {username}\n"
        return RenderedEmail(
            subject="Activate your Nebula account",
            body=(
                "Your Nebula account request was approved.\n\n"
                "This account:\n"
                f"{identifiers}\n"
                "To finish setting it up:\n\n"
                "  1. Open the Nebula app.\n"
                '  2. On the sign-in screen, tap "Have an activation code? '
                'Activate".\n'
                "  3. Enter the activation code below.\n"
                '  4. Choose the password you want, then tap "Activate".\n\n'
                f"Activation code:\n  {token}\n\n"
                # Said outright because the previous email's silence on it read
                # as "a password was issued and is missing from this email".
                "You choose your own password in step 4. No password has been\n"
                "created for you, and nobody here can see or set it.\n\n"
                "After activating, sign in with the password you just chose.\n\n"
                f"This code works once and expires at {expires_at}.\n"
                "If it expires, ask an administrator to approve a new request.\n"
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
