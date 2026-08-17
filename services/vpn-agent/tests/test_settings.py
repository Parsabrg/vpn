from pathlib import PurePosixPath

import pytest
from pydantic import ValidationError

from nebula_agent.settings import Settings


def test_xray_cannot_be_enabled_before_delivery_milestone() -> None:
    with pytest.raises(ValidationError, match="Xray is disabled"):
        Settings(xray_enabled=True)


def test_host_paths_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="host paths must be absolute"):
        Settings(xray_binary=PurePosixPath("bin/xray"))


def test_invalid_interface_name_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Linux interface"):
        Settings(wg_interface="wg0; shutdown")


def test_unknown_explicit_setting_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Settings(command="id")  # type: ignore[call-arg]


def test_public_endpoint_rejects_a_url_with_a_scheme() -> None:
    with pytest.raises(ValidationError, match="bare host:port"):
        Settings(wg_public_endpoint="https://vpn.example.com:51820")


def test_public_endpoint_rejects_shell_metacharacters() -> None:
    with pytest.raises(ValidationError, match="bare host:port"):
        Settings(wg_public_endpoint="vpn.example.com:51820; rm -rf /")


def test_public_endpoint_rejects_an_out_of_range_port() -> None:
    with pytest.raises(ValidationError, match="port must be between 1 and 65535"):
        Settings(wg_public_endpoint="vpn.example.com:99999")


def test_client_allowed_ips_rejects_an_empty_segment() -> None:
    with pytest.raises(ValidationError, match="comma-separated list of CIDR networks"):
        Settings(wg_client_allowed_ips="0.0.0.0/0,")


def test_client_allowed_ips_rejects_an_invalid_cidr() -> None:
    with pytest.raises(ValidationError, match="invalid CIDR network"):
        Settings(wg_client_allowed_ips="not-a-cidr")


def test_client_allowed_ips_accepts_a_valid_list() -> None:
    settings = Settings(wg_client_allowed_ips="10.0.0.0/8,fd00::/8")
    assert settings.wg_client_allowed_ips == "10.0.0.0/8,fd00::/8"


def test_server_address_must_fall_inside_client_pool() -> None:
    with pytest.raises(ValidationError, match="wg_server_address must fall inside wg_client_pool"):
        Settings(wg_server_address="192.168.1.1/24", wg_client_pool="10.77.0.0/24")
