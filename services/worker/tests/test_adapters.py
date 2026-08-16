import asyncio
import json
import smtplib
import urllib.error
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nebula_worker.adapters.base import EmailSendError
from nebula_worker.adapters.resend import ResendAdapter
from nebula_worker.adapters.smtp import SmtpAdapter
from nebula_worker.settings import Settings


def test_smtp_adapter_sends_and_returns_a_message_id() -> None:
    settings = Settings(smtp_host="mailpit", smtp_port=1025)
    adapter = SmtpAdapter(settings)
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.__exit__.return_value = False

    with patch("smtplib.SMTP", return_value=fake_smtp) as constructor:
        message_id = asyncio.run(
            adapter.send(to="user@example.com", subject="Subject", body="Body")
        )

    constructor.assert_called_once_with("mailpit", 1025, timeout=10)
    fake_smtp.send_message.assert_called_once()
    assert message_id.startswith("<") and message_id.endswith("@nebula-worker>")


def test_smtp_adapter_uses_starttls_and_login_when_configured(tmp_path: Any) -> None:
    password_file = tmp_path / "smtp_password"
    password_file.write_text("secret", encoding="utf-8")
    settings = Settings(
        smtp_starttls=True, smtp_username="worker", smtp_password_file=password_file
    )
    adapter = SmtpAdapter(settings)
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.__exit__.return_value = False

    with patch("smtplib.SMTP", return_value=fake_smtp):
        asyncio.run(adapter.send(to="user@example.com", subject="Subject", body="Body"))

    fake_smtp.starttls.assert_called_once()
    fake_smtp.login.assert_called_once_with("worker", "secret")


def test_smtp_adapter_wraps_failures() -> None:
    settings = Settings()
    adapter = SmtpAdapter(settings)

    with patch("smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, "down")):
        with pytest.raises(EmailSendError):
            asyncio.run(adapter.send(to="user@example.com", subject="Subject", body="Body"))


def test_resend_adapter_sends_and_returns_provider_message_id(tmp_path: Any) -> None:
    key_file = tmp_path / "resend_api_key"
    key_file.write_text("re_canary", encoding="utf-8")
    settings = Settings(email_provider="resend", resend_api_key_file=key_file)
    adapter = ResendAdapter(settings)
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.read.return_value = json.dumps({"id": "resend-message-id"}).encode("utf-8")

    with patch("urllib.request.urlopen", return_value=response):
        message_id = asyncio.run(
            adapter.send(to="user@example.com", subject="Subject", body="Body")
        )

    assert message_id == "resend-message-id"


def test_resend_adapter_wraps_transport_failures(tmp_path: Any) -> None:
    key_file = tmp_path / "resend_api_key"
    key_file.write_text("re_canary", encoding="utf-8")
    settings = Settings(email_provider="resend", resend_api_key_file=key_file)
    adapter = ResendAdapter(settings)

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
        with pytest.raises(EmailSendError):
            asyncio.run(adapter.send(to="user@example.com", subject="Subject", body="Body"))


def test_resend_adapter_rejects_a_non_string_message_id(tmp_path: Any) -> None:
    key_file = tmp_path / "resend_api_key"
    key_file.write_text("re_canary", encoding="utf-8")
    settings = Settings(email_provider="resend", resend_api_key_file=key_file)
    adapter = ResendAdapter(settings)
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.read.return_value = json.dumps({"id": 12345}).encode("utf-8")

    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(EmailSendError):
            asyncio.run(adapter.send(to="user@example.com", subject="Subject", body="Body"))


def test_resend_adapter_rejects_an_unparseable_response(tmp_path: Any) -> None:
    key_file = tmp_path / "resend_api_key"
    key_file.write_text("re_canary", encoding="utf-8")
    settings = Settings(email_provider="resend", resend_api_key_file=key_file)
    adapter = ResendAdapter(settings)
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.read.return_value = b"not-json"

    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(EmailSendError):
            asyncio.run(adapter.send(to="user@example.com", subject="Subject", body="Body"))
