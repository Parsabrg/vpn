"""Stdlib-only Resend HTTP adapter (no SDK dependency for one JSON POST)."""

import asyncio
import json
import urllib.error
import urllib.request

from nebula_worker.adapters.base import EmailSendError
from nebula_worker.settings import Settings

_RESEND_ENDPOINT = "https://api.resend.com/emails"


class ResendAdapter:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send(self, *, to: str, subject: str, body: str) -> str:
        return await asyncio.to_thread(self._send_sync, to, subject, body)

    def _send_sync(self, to: str, subject: str, body: str) -> str:
        payload = json.dumps(
            {"from": self._settings.email_from, "to": [to], "subject": subject, "text": body}
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - fixed https endpoint, not user input
            _RESEND_ENDPOINT,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._settings.resend_api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                body_bytes = response.read()
        except (urllib.error.URLError, TimeoutError) as error:
            raise EmailSendError("Resend delivery failed") from error
        try:
            decoded = json.loads(body_bytes)
            message_id = decoded["id"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise EmailSendError("Resend response was not understood") from error
        if not isinstance(message_id, str):
            raise EmailSendError("Resend response was not understood")
        return message_id
