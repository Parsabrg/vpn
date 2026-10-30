from pathlib import PurePosixPath

import pytest
from pydantic import ValidationError

from nebula_agent.settings import Settings


def test_xray_can_be_enabled_with_the_fake_driver() -> None:
    settings = Settings(xray_enabled=True, xray_driver="fake")
    assert settings.xray_enabled is True
    assert settings.xray_driver == "fake"


def test_xray_driver_rejects_an_unknown_value() -> None:
    with pytest.raises(ValidationError):
        Settings(xray_driver="unknown")


def test_xray_xhttp_path_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="absolute path"):
        Settings(xray_xhttp_path="xhttp")


def test_xray_public_host_rejects_a_url_with_a_scheme() -> None:
    with pytest.raises(ValidationError, match="bare hostname"):
        Settings(xray_public_host="https://vpn.example.com")


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


def test_build_xray_inbound_profiles_includes_only_xhttp_by_default() -> None:
    settings = Settings()
    profiles = settings.build_xray_inbound_profiles()
    assert [p.protocol_profile_code for p in profiles] == ["vless-xhttp-tls"]
    assert profiles[0].security == "none"
    assert profiles[0].listen == "127.0.0.1"


def test_build_xray_inbound_profiles_includes_enabled_transports() -> None:
    settings = Settings(
        xray_grpc_enabled=True,
        xray_ws_enabled=True,
        xray_tcp_enabled=True,
        xray_tls_cert_file=PurePosixPath("/run/nebula-secrets/xray_tls_cert"),
        xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
    )
    profiles = settings.build_xray_inbound_profiles()
    codes = {p.protocol_profile_code for p in profiles}
    assert codes == {
        "vless-xhttp-tls",
        "vless-grpc-tls",
        "vless-ws-tls",
        "vless-tcp-tls",
    }
    grpc = next(p for p in profiles if p.protocol_profile_code == "vless-grpc-tls")
    assert grpc.security == "tls"
    assert grpc.listen == "0.0.0.0"  # noqa: S104
    assert grpc.grpc_service_name == "grpc"


def test_direct_terminating_transport_requires_tls_material() -> None:
    with pytest.raises(ValidationError, match="xray_tls_cert_file and xray_tls_key_file"):
        Settings(xray_grpc_enabled=True)


def test_hysteria_requires_tls_material() -> None:
    with pytest.raises(ValidationError, match="xray_tls_cert_file and xray_tls_key_file"):
        Settings(xray_hysteria_enabled=True)


def test_hysteria_is_not_an_xray_inbound() -> None:
    """Hysteria2 is served by the standalone binary, not Xray-core.

    Xray accepts the obfuscation setting and silently discards it -- a client
    with a deliberately wrong Salamander password authenticates -- so an
    inbound configured for obfuscation has none. It must not appear among the
    Xray inbounds even when the transport is enabled.
    """

    settings = Settings(
        xray_hysteria_enabled=True,
        xray_hysteria_obfs_password="s3cret-salamander",  # noqa: S106 - test fixture, not real
        xray_tls_cert_file=PurePosixPath("/run/nebula-secrets/xray_tls_cert"),
        xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
    )
    codes = {p.protocol_profile_code for p in settings.build_xray_inbound_profiles()}
    assert "hysteria2" not in codes


def test_hysteria_server_profile_when_enabled() -> None:
    settings = Settings(
        xray_hysteria_enabled=True,
        xray_hysteria_obfs_password="s3cret-salamander",  # noqa: S106 - test fixture, not real
        xray_tls_cert_file=PurePosixPath("/run/nebula-secrets/xray_tls_cert"),
        xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
    )
    profile = settings.hysteria_server_profile()
    assert profile is not None
    assert profile.protocol_profile_code == "hysteria2"
    assert profile.port == 8450
    assert profile.up_mbps == 100
    assert profile.down_mbps == 100
    assert profile.obfs_password == "s3cret-salamander"  # noqa: S105
    assert profile.tls_cert_file == "/run/nebula-secrets/xray_tls_cert"


def test_hysteria_server_profile_is_none_when_disabled() -> None:
    assert Settings().hysteria_server_profile() is None


def test_hysteria_requires_obfs_password() -> None:
    with pytest.raises(ValidationError, match="xray_hysteria_obfs_password"):
        Settings(
            xray_hysteria_enabled=True,
            xray_tls_cert_file=PurePosixPath("/run/nebula-secrets/xray_tls_cert"),
            xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
        )


def test_hysteria_port_must_be_distinct() -> None:
    with pytest.raises(ValidationError, match="must all be distinct"):
        Settings(
            xray_hysteria_enabled=True,
            xray_hysteria_port=8446,  # collides with xray_local_listen_port's default
            xray_hysteria_obfs_password="s3cret-salamander",  # noqa: S106 - test fixture
            xray_tls_cert_file=PurePosixPath("/run/nebula-secrets/xray_tls_cert"),
            xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
        )


def test_direct_terminating_transport_ports_must_be_distinct() -> None:
    with pytest.raises(ValidationError, match="must all be distinct"):
        Settings(
            xray_grpc_enabled=True,
            xray_grpc_port=8446,  # collides with xray_local_listen_port's default
            xray_tls_cert_file=PurePosixPath("/run/nebula-secrets/xray_tls_cert"),
            xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
        )


def test_xray_ws_path_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="absolute path"):
        Settings(xray_ws_path="ws")


def test_xray_grpc_service_name_rejects_unsafe_characters() -> None:
    with pytest.raises(ValidationError, match="safe gRPC service name"):
        Settings(xray_grpc_service_name="not a service name!")


def test_xray_tls_paths_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="host paths must be absolute"):
        Settings(
            xray_grpc_enabled=True,
            xray_tls_cert_file=PurePosixPath("cert"),
            xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
        )
