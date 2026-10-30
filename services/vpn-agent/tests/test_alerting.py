"""The alert sender, tested on the paths where it can fail quietly.

A monitor that cannot report is indistinguishable from a healthy system, so
every failure here has to be loud. These pin that: nothing is swallowed, and
"sent" is only claimed when Resend actually acknowledged a message.
"""

import io
import json
import urllib.error
from pathlib import Path

import pytest

from nebula_agent.alerting import AlertNotSent, Mailer

# String target rather than the module attribute: mypy runs with
# no_implicit_reexport, so reaching urllib through the module under test
# is an error even though it is exactly what is being patched.
_URLOPEN = "nebula_agent.alerting.urllib.request.urlopen"


def _mailer() -> Mailer:
    return Mailer(api_key="key", sender="Nebula <no-reply@example.org>", recipient="me@example.org")


class _Response:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_a_sent_alert_returns_the_message_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["body"] = json.loads(request.data)  # type: ignore[attr-defined]
        captured["headers"] = request.headers  # type: ignore[attr-defined]
        return _Response(b'{"id": "msg_123"}')

    monkeypatch.setattr(_URLOPEN, _urlopen)

    assert _mailer().send(subject="s", body="b") == "msg_123"
    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["body"] == {
        "from": "Nebula <no-reply@example.org>",
        "to": ["me@example.org"],
        "subject": "s",
        "text": "b",
    }


def test_the_user_agent_is_not_the_urllib_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resend sits behind Cloudflare, which blocks Python-urllib's default
    User-Agent outright with a generic 403 and no application detail. The
    worker hit this against a real deployment; the alert path would have hit
    it the first time something broke."""

    seen: dict[str, str] = {}

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        seen.update(request.headers)  # type: ignore[attr-defined]
        return _Response(b'{"id": "msg_123"}')

    monkeypatch.setattr(_URLOPEN, _urlopen)
    _mailer().send(subject="s", body="b")

    agent = seen.get("User-agent", "")
    assert agent.startswith("nebula-agent/")


def test_a_network_failure_raises_rather_than_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _urlopen(request: object, timeout: float = 0) -> _Response:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(_URLOPEN, _urlopen)

    with pytest.raises(AlertNotSent, match="Resend delivery failed"):
        _mailer().send(subject="s", body="b")


def test_a_non_json_response_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_URLOPEN, lambda *_a, **_k: _Response(b"<html>502</html>"))

    with pytest.raises(AlertNotSent, match="not JSON"):
        _mailer().send(subject="s", body="b")


def test_a_response_without_a_message_id_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 with no id means Resend did not accept it. Reporting success there
    would let the health check believe someone was told."""

    monkeypatch.setattr(_URLOPEN, lambda *_a, **_k: _Response(b'{"error": "nope"}'))

    with pytest.raises(AlertNotSent, match="no message id"):
        _mailer().send(subject="s", body="b")


def test_a_missing_api_key_file_raises_before_any_request(tmp_path: Path) -> None:
    with pytest.raises(AlertNotSent, match="could not read"):
        Mailer.from_files(tmp_path / "absent", "from", "to")


def test_an_empty_api_key_file_raises(tmp_path: Path) -> None:
    """An empty key would fail at Resend with a 401 the health check reports as
    a delivery failure. Saying which file is empty is the more useful error."""

    key = tmp_path / "key"
    key.write_text("   \n")

    with pytest.raises(AlertNotSent, match="is empty"):
        Mailer.from_files(key, "from", "to")


def test_the_key_is_read_and_stripped(tmp_path: Path) -> None:
    key = tmp_path / "key"
    key.write_text("re_secret\n")

    mailer = Mailer.from_files(key, "from", "to")

    assert mailer.api_key == "re_secret"


def test_the_key_never_appears_in_the_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Alert failures land in the journal, which is not where a Resend API key
    should end up."""

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        raise urllib.error.URLError("bad auth")

    monkeypatch.setattr(_URLOPEN, _urlopen)
    mailer = Mailer(api_key="re_supersecret", sender="f", recipient="t")

    with pytest.raises(AlertNotSent) as caught:
        mailer.send(subject="s", body="b")

    assert "re_supersecret" not in str(caught.value)
    assert "re_supersecret" not in repr(caught.value.__cause__ or "")


def test_the_body_is_utf8_encoded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Problem details carry unit names and journal output, which is not
    guaranteed to be ASCII."""

    seen: dict[str, object] = {}

    def _urlopen(request: object, timeout: float = 0) -> _Response:
        seen["data"] = request.data  # type: ignore[attr-defined]
        return _Response(b'{"id": "msg_1"}')

    monkeypatch.setattr(_URLOPEN, _urlopen)
    _mailer().send(subject="s", body="café — naïve")

    assert isinstance(seen["data"], bytes)
    assert json.loads(io.BytesIO(seen["data"]).read())["text"] == "café — naïve"
