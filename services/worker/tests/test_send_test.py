from unittest.mock import AsyncMock, patch

import pytest

from nebula_worker.adapters.base import EmailSendError
from nebula_worker.send_test import SUBJECT, main


def test_sends_one_message_and_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    adapter = AsyncMock()
    adapter.send.return_value = "id-1"
    with patch("nebula_worker.send_test.build_adapter", return_value=adapter):
        assert main(["owner@example.test"]) == 0
    adapter.send.assert_awaited_once()
    assert adapter.send.await_args.kwargs["to"] == "owner@example.test"
    assert adapter.send.await_args.kwargs["subject"] == SUBJECT
    assert "sent to owner@example.test" in capsys.readouterr().out


def test_a_refusal_is_reported_not_raised(capsys: pytest.CaptureFixture[str]) -> None:
    adapter = AsyncMock()
    adapter.send.side_effect = EmailSendError("Resend rejected the message: 403")
    with patch("nebula_worker.send_test.build_adapter", return_value=adapter):
        assert main(["owner@example.test"]) == 1
    assert "not sent: Resend rejected the message: 403" in capsys.readouterr().err


@pytest.mark.parametrize("args", [[], ["not-an-address"], ["a@b", "c@d"]])
def test_needs_one_address(args: list[str]) -> None:
    assert main(args) == 2
