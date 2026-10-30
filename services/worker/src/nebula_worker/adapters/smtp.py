"""Stdlib-only SMTP adapter (no new runtime dependency)."""

import asyncio
import smtplib
import uuid
from email.message import EmailMessage

from nebula_worker.adapters.base import EmailSendError
from nebula_worker.settings import Settings


class SmtpAdapter:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send(self, *, to: str, subject: str, body: str) -> str:
        try:
            return await asyncio.to_thread(self._send_sync, to, subject, body)
        except (OSError, smtplib.SMTPException) as error:
            raise EmailSendError("SMTP delivery failed") from error

    def _send_sync(self, to: str, subject: str, body: str) -> str:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._settings.email_from
        message["To"] = to
        message_id = f"<{uuid.uuid4()}@nebula-worker>"
        message["Message-ID"] = message_id
        message.set_content(body)

        with smtplib.SMTP(self._settings.smtp_host, self._settings.smtp_port, timeout=10) as smtp:
            if self._settings.smtp_starttls:
                smtp.starttls()
            password = self._settings.smtp_password
            if self._settings.smtp_username and password:
                smtp.login(self._settings.smtp_username, password)
            smtp.send_message(message)
        return message_id
