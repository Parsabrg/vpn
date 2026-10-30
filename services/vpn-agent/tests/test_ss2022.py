"""Shadowsocks-2022: an inbound with no TLS whose traffic looks random.

Iran let it through to the very address whose TLS it stalls (home line,
2026-10-22), so it is served beside the VLESS transports, its users added and
removed live the same way.
"""

import asyncio
import base64
import json
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest
from pydantic import ValidationError
from test_drivers_xray import _provision_request
from test_drivers_xray_live import FakeXray

import nebula_agent.drivers.xray as xray
from nebula_agent.drivers.xray import NativeXrayDriver
from nebula_agent.drivers.xray_base import RevokeXrayClientRequest
from nebula_agent.drivers.xray_config_store import (
    XrayConfigStore,
    client_email,
    ss2022_user_key,
    uuid_from_ss2022_key,
)
from nebula_agent.settings import Settings

_KEY = base64.b64encode(bytes(range(16))).decode()
_CODE = "shadowsocks-2022"


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "env": "test",
        "xray_ss2022_enabled": True,
        "xray_ss2022_server_key": _KEY,
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


def test_a_client_key_is_its_uuid_and_reads_back() -> None:
    client_uuid = uuid4()
    key = ss2022_user_key(client_uuid)
    assert len(base64.b64decode(key)) == 16
    assert uuid_from_ss2022_key(key) == client_uuid


@pytest.mark.parametrize("key", [None, "not base64!", base64.b64encode(b"short").decode()])
def test_enabled_needs_a_sixteen_byte_server_key(key: str | None) -> None:
    with pytest.raises(ValidationError, match="xray_ss2022_server_key"):
        _settings(xray_ss2022_server_key=key)


def test_its_port_must_be_its_own() -> None:
    with pytest.raises(ValidationError, match="distinct"):
        _settings(xray_ss2022_port=9443)


def test_off_by_default() -> None:
    settings = Settings(env="test")
    assert _CODE not in {p.protocol_profile_code for p in settings.build_xray_inbound_profiles()}


def test_provision_serves_shadowsocks_and_hands_out_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, _fake = _setup(tmp_path, monkeypatch)
    request = _provision_request(protocol_profile_code=_CODE)

    response = asyncio.run(driver.provision_client(request))

    assert response.state == "active"
    assert response.protocol == "shadowsocks"
    assert response.method == "2022-blake3-aes-128-gcm"
    assert response.password == f"{_KEY}:{ss2022_user_key(request.client_uuid)}"
    # Dialled directly: not the nginx-fronted port, and no TLS.
    assert response.port == 8451
    assert response.transport == "raw"
    assert response.transport_security == "none"

    served = json.loads(driver._config_store.xray_config_path.read_text())
    inbound = next(i for i in served["inbounds"] if i["tag"] == _CODE)
    assert inbound["protocol"] == "shadowsocks"
    assert inbound["listen"] == "0.0.0.0"  # noqa: S104 - asserting the public bind
    assert inbound["settings"]["password"] == _KEY
    assert inbound["settings"]["clients"] == [
        {
            "password": ss2022_user_key(request.client_uuid),
            "email": client_email(request.client_uuid),
        }
    ]
    assert "tlsSettings" not in inbound["streamSettings"]
    assert driver._live_client_uuids(driver._profile_for(_CODE)) == {str(request.client_uuid)}


def test_a_vless_client_gets_no_shadowsocks_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, _fake = _setup(tmp_path, monkeypatch)

    response = asyncio.run(driver.provision_client(_provision_request()))

    assert response.protocol == "vless"
    assert response.method is None and response.password is None


def test_users_come_and_go_without_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch)
    first = _provision_request(protocol_profile_code=_CODE)
    second = _provision_request(protocol_profile_code=_CODE)

    async def scenario() -> None:
        await driver.provision_client(first)
        await driver.provision_client(second)
        await driver.revoke_client(
            RevokeXrayClientRequest(
                idempotency_key=uuid4(),
                correlation_id=uuid4(),
                target_kind="xray_client",
                target_id=uuid4(),
                client_uuid=first.client_uuid,
                protocol_profile_code=_CODE,
                desired_generation=1,
            )
        )

    asyncio.run(scenario())

    # One restart, for the first client ever; the rest went through the API.
    assert fake.restarts == 1
    assert fake.served_emails(_CODE) == {client_email(second.client_uuid)}
    added = json.loads(fake.stdin[-1])["inbounds"][0]
    # `adu` builds the user from the inbound's own settings, key and method.
    assert added["protocol"] == "shadowsocks"
    assert added["settings"]["method"] == "2022-blake3-aes-128-gcm"
    assert added["settings"]["password"] == _KEY
