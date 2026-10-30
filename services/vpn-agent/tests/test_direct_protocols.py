"""VLESS Encryption and VMess: direct profiles with their own encryption.

Like Shadowsocks-2022 (test_ss2022.py), Iran let them through to the very
address whose TLS it stalls (home line, 2026-10-22), so they are served on
their own public ports and their users change live.
"""

import asyncio
import json
from pathlib import Path, PurePosixPath

import pytest
from pydantic import ValidationError
from test_drivers_xray import _provision_request
from test_drivers_xray_live import FakeXray

import nebula_agent.drivers.xray as xray
from nebula_agent.drivers.xray import NativeXrayDriver
from nebula_agent.drivers.xray_config_store import XrayConfigStore, client_email
from nebula_agent.settings import Settings

_DEC = "mlkem768x25519plus.native.600s.server-key"
_ENC = "mlkem768x25519plus.native.0rtt.client-key"


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "env": "test",
        "xray_vlessenc_enabled": True,
        "xray_vlessenc_decryption": _DEC,
        "xray_vlessenc_encryption": _ENC,
        "xray_vmess_enabled": True,
        "xray_live_client_updates": True,
        "xray_api_host": "127.25.41.4",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[NativeXrayDriver, FakeXray]:
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    driver = NativeXrayDriver(_settings(), store)
    fake = FakeXray(driver)
    monkeypatch.setattr(xray, "run_fixed_argv", fake)
    monkeypatch.setattr(xray, "_LINGER_POLL_SECONDS", 0.0)
    return driver, fake


def _inbound(driver: NativeXrayDriver, tag: str) -> dict[str, object]:
    served = json.loads(driver._config_store.xray_config_path.read_text())
    return next(i for i in served["inbounds"] if i["tag"] == tag)


@pytest.mark.parametrize(
    "overrides",
    [
        {"xray_vlessenc_decryption": None},
        {"xray_vlessenc_encryption": "none"},
    ],
)
def test_vless_encryption_needs_its_key_pair(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="xray_vlessenc"):
        _settings(**overrides)


def test_ports_must_be_their_own() -> None:
    with pytest.raises(ValidationError, match="distinct"):
        _settings(xray_vmess_ws_port=8453)


def test_vless_encryption_hands_out_its_client_string(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, _fake = _setup(tmp_path, monkeypatch)
    request = _provision_request(protocol_profile_code="vless-enc")

    response = asyncio.run(driver.provision_client(request))

    assert response.state == "active"
    assert response.protocol == "vless"
    assert response.encryption == _ENC
    assert (response.port, response.transport, response.transport_security) == (8453, "raw", "none")
    inbound = _inbound(driver, "vless-enc")
    assert inbound["settings"]["decryption"] == _DEC  # type: ignore[index]
    assert "tlsSettings" not in inbound["streamSettings"]  # type: ignore[operator]


@pytest.mark.parametrize(
    ("code", "port", "transport", "path"),
    [("vmess-raw", 8454, "raw", None), ("vmess-ws", 8455, "websocket", "/vw")],
)
def test_vmess_is_served_directly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    port: int,
    transport: str,
    path: str | None,
) -> None:
    driver, _fake = _setup(tmp_path, monkeypatch)
    request = _provision_request(protocol_profile_code=code)

    response = asyncio.run(driver.provision_client(request))

    assert response.protocol == "vmess"
    assert response.encryption is None and response.password is None
    assert (response.port, response.transport, response.path) == (port, transport, path)
    assert response.transport_security == "none"
    inbound = _inbound(driver, code)
    assert inbound["protocol"] == "vmess"
    assert inbound["settings"] == {
        "clients": [{"id": str(request.client_uuid), "email": client_email(request.client_uuid)}]
    }
    assert driver._live_client_uuids(driver._profile_for(code)) == {str(request.client_uuid)}


def test_plain_vless_keeps_no_encryption(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver, _fake = _setup(tmp_path, monkeypatch)

    response = asyncio.run(driver.provision_client(_provision_request()))

    assert response.encryption is None
    assert _inbound(driver, "vless-xhttp-tls")["settings"]["decryption"] == "none"  # type: ignore[index]


def test_vmess_users_change_without_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch)
    first = _provision_request(protocol_profile_code="vmess-ws")
    second = _provision_request(protocol_profile_code="vmess-ws")

    async def scenario() -> None:
        await driver.provision_client(first)
        await driver.provision_client(second)

    asyncio.run(scenario())

    assert fake.restarts == 1
    assert fake.served_emails("vmess-ws") == {
        client_email(first.client_uuid),
        client_email(second.client_uuid),
    }
    added = json.loads(fake.stdin[-1])["inbounds"][0]
    assert added["protocol"] == "vmess"
