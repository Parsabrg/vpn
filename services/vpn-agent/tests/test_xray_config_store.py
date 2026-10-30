import json
import os
from pathlib import Path, PurePosixPath
from uuid import UUID

import pytest

from nebula_agent.drivers.xray_config_store import (
    DesiredXrayState,
    RenderedXrayClient,
    XrayConfigStore,
    XrayInboundProfile,
    parse_state_json,
    render_state_json,
    render_xray_server_config,
)

XHTTP_PROFILE = XrayInboundProfile(
    protocol_profile_code="vless-xhttp-tls",
    transport="xhttp",
    listen="127.0.0.1",
    port=8446,
    security="none",
    xhttp_path="/xhttp",
)
GRPC_PROFILE = XrayInboundProfile(
    protocol_profile_code="vless-grpc-tls",
    transport="grpc",
    listen="0.0.0.0",  # noqa: S104 - deliberately public, mirrors settings.py
    port=8447,
    security="tls",
    grpc_service_name="grpc",
)
WS_PROFILE = XrayInboundProfile(
    protocol_profile_code="vless-ws-tls",
    transport="websocket",
    listen="0.0.0.0",  # noqa: S104 - deliberately public, mirrors settings.py
    port=8448,
    security="tls",
    ws_path="/ws",
)
TCP_PROFILE = XrayInboundProfile(
    protocol_profile_code="vless-tcp-tls",
    transport="raw",
    listen="0.0.0.0",  # noqa: S104 - deliberately public, mirrors settings.py
    port=8449,
    security="tls",
)
HYSTERIA_PROFILE = XrayInboundProfile(
    protocol_profile_code="hysteria2",
    transport="hysteria",
    listen="0.0.0.0",  # noqa: S104 - deliberately public, mirrors settings.py
    port=8450,
    security="tls",
    hysteria_up_mbps=100,
    hysteria_down_mbps=100,
)

CLIENT_A = RenderedXrayClient(
    client_uuid=UUID(int=1), protocol_profile_code="vless-xhttp-tls", generation=1
)
CLIENT_B = RenderedXrayClient(client_uuid=UUID(int=2), protocol_profile_code="vless-xhttp-tls")
CLIENT_C = RenderedXrayClient(client_uuid=UUID(int=3), protocol_profile_code="vless-grpc-tls")


def test_with_client_adds_a_new_client() -> None:
    state = DesiredXrayState().with_client(CLIENT_A)
    assert state.clients == (CLIENT_A,)


def test_with_client_replaces_an_existing_client_by_uuid() -> None:
    updated = RenderedXrayClient(
        client_uuid=CLIENT_A.client_uuid, protocol_profile_code="vless-xhttp-tls", generation=9
    )
    state = DesiredXrayState(clients=(CLIENT_A,)).with_client(updated)
    assert state.clients == (updated,)


def test_without_client_removes_by_uuid() -> None:
    state = DesiredXrayState(clients=(CLIENT_A, CLIENT_B)).without_client(CLIENT_A.client_uuid)
    assert state.clients == (CLIENT_B,)


def test_render_and_parse_state_round_trip() -> None:
    state = DesiredXrayState(clients=(CLIENT_A, CLIENT_B))
    text = render_state_json(state)
    assert parse_state_json(text) == state


def test_empty_state_renders_and_parses_to_no_clients() -> None:
    assert parse_state_json(render_state_json(DesiredXrayState())) == DesiredXrayState()


def test_render_xray_server_config_includes_every_client_uuid_on_its_own_inbound() -> None:
    state = DesiredXrayState(clients=(CLIENT_A, CLIENT_B, CLIENT_C))
    config = json.loads(
        render_xray_server_config(
            state, (XHTTP_PROFILE, GRPC_PROFILE), tls_cert_file="/cert", tls_key_file="/key"
        )
    )

    # Two profile inbounds plus the loopback stats inbound.
    assert len(config["inbounds"]) == 3
    xhttp_inbound = next(i for i in config["inbounds"] if i["port"] == 8446)
    grpc_inbound = next(i for i in config["inbounds"] if i["port"] == 8447)

    xhttp_ids = {c["id"] for c in xhttp_inbound["settings"]["clients"]}
    assert xhttp_ids == {str(CLIENT_A.client_uuid), str(CLIENT_B.client_uuid)}
    assert xhttp_inbound["listen"] == "127.0.0.1"
    assert xhttp_inbound["streamSettings"]["xhttpSettings"]["path"] == "/xhttp"
    assert xhttp_inbound["streamSettings"]["security"] == "none"
    assert "tlsSettings" not in xhttp_inbound["streamSettings"]

    grpc_ids = {c["id"] for c in grpc_inbound["settings"]["clients"]}
    assert grpc_ids == {str(CLIENT_C.client_uuid)}
    assert grpc_inbound["listen"] == "0.0.0.0"  # noqa: S104
    assert grpc_inbound["streamSettings"]["grpcSettings"]["serviceName"] == "grpc"
    assert grpc_inbound["streamSettings"]["security"] == "tls"
    assert grpc_inbound["streamSettings"]["tlsSettings"]["certificates"] == [
        {"certificateFile": "/cert", "keyFile": "/key"}
    ]


def test_render_xray_server_config_with_no_clients_has_an_empty_client_list() -> None:
    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(), (XHTTP_PROFILE,), tls_cert_file=None, tls_key_file=None
        )
    )
    assert config["inbounds"][0]["settings"]["clients"] == []


def test_render_xray_server_config_renders_websocket_and_raw_transports() -> None:
    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(),
            (WS_PROFILE, TCP_PROFILE),
            tls_cert_file="/cert",
            tls_key_file="/key",
        )
    )
    ws_inbound = next(i for i in config["inbounds"] if i["port"] == 8448)
    tcp_inbound = next(i for i in config["inbounds"] if i["port"] == 8449)

    assert ws_inbound["streamSettings"]["wsSettings"]["path"] == "/ws"
    assert ws_inbound["streamSettings"]["network"] == "websocket"
    assert tcp_inbound["streamSettings"]["network"] == "raw"
    assert "wsSettings" not in tcp_inbound["streamSettings"]
    assert "grpcSettings" not in tcp_inbound["streamSettings"]
    assert "xhttpSettings" not in tcp_inbound["streamSettings"]


def test_render_xray_server_config_renders_hysteria_transport() -> None:
    client = RenderedXrayClient(client_uuid=UUID(int=4), protocol_profile_code="hysteria2")
    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(clients=(client,)),
            (HYSTERIA_PROFILE,),
            tls_cert_file="/cert",
            tls_key_file="/key",
        )
    )
    inbound = config["inbounds"][0]

    assert inbound["protocol"] == "hysteria"
    assert inbound["settings"] == {"version": 2, "clients": [{"auth": str(client.client_uuid)}]}
    assert inbound["streamSettings"]["network"] == "hysteria"
    assert inbound["streamSettings"]["hysteriaSettings"] == {
        "version": 2,
        "up": "100",
        "down": "100",
    }
    assert inbound["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert inbound["streamSettings"]["tlsSettings"]["certificates"] == [
        {"certificateFile": "/cert", "keyFile": "/key"}
    ]
    assert "udpmasks" not in inbound["streamSettings"]


def test_render_xray_server_config_renders_hysteria_obfs_password_as_udpmasks() -> None:
    profile = XrayInboundProfile(
        protocol_profile_code="hysteria2",
        transport="hysteria",
        listen="0.0.0.0",  # noqa: S104 - deliberately public, mirrors settings.py
        port=8450,
        security="tls",
        hysteria_up_mbps=100,
        hysteria_down_mbps=100,
        hysteria_obfs_password="s3cret-salamander",  # noqa: S106 - test fixture, not real
    )
    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(), (profile,), tls_cert_file="/cert", tls_key_file="/key"
        )
    )
    inbound = config["inbounds"][0]

    assert inbound["streamSettings"]["udpmasks"] == [
        {"type": "salamander", "settings": {"password": "s3cret-salamander"}}
    ]


def test_clients_for_filters_by_profile_code() -> None:
    state = DesiredXrayState(clients=(CLIENT_A, CLIENT_B, CLIENT_C))
    assert state.clients_for("vless-xhttp-tls") == (CLIENT_A, CLIENT_B)
    assert state.clients_for("vless-grpc-tls") == (CLIENT_C,)
    assert state.clients_for("vless-ws-tls") == ()


def test_read_last_known_good_is_empty_before_anything_is_promoted(tmp_path: Path) -> None:
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    assert store.read_last_known_good() == DesiredXrayState()


def test_write_and_promote_round_trips_through_read_last_known_good(tmp_path: Path) -> None:
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    state = DesiredXrayState(clients=(CLIENT_A,))

    text = store.render_candidate(state)
    candidate = store.write_candidate_atomically(text)
    assert candidate.exists()
    assert not store.last_known_good_path.exists()

    store.promote_candidate_to_last_known_good(candidate)
    assert store.last_known_good_path.exists()
    assert not candidate.exists()
    assert store.read_last_known_good() == state


def test_write_candidate_atomically_leaves_no_temp_file_on_success(tmp_path: Path) -> None:
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    store.write_candidate_atomically("[]")

    remaining = {path.name for path in (tmp_path / "state" / "candidate").iterdir()}
    assert remaining == {"xray_clients_state.json"}


def test_write_candidate_atomically_cleans_up_the_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )

    def failing_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError, match="simulated rename failure"):
        store.write_candidate_atomically("[]")

    assert list((tmp_path / "state" / "candidate").iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode bits are not meaningful on Windows")
def test_write_xray_config_atomically_is_group_readable_not_world_readable(
    tmp_path: Path,
) -> None:
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )

    written = store.write_xray_config_atomically('{"inbounds": []}')

    assert oct(written.stat().st_mode)[-3:] == "640"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode bits are not meaningful on Windows")
def test_write_validate_scratch_atomically_keeps_the_default_owner_only_mode(
    tmp_path: Path,
) -> None:
    # Unlike the real config file, the validation scratch copy is only ever
    # read by a subprocess this same driver spawns (see drivers/xray.py's
    # `_validate`) -- no cross-user access needed, so mkstemp's default 0600
    # is fine here and deliberately left alone.
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )

    written = store.write_validate_scratch_atomically('{"inbounds": []}')

    assert oct(written.stat().st_mode)[-3:] == "600"


def test_the_served_config_refuses_to_dial_this_host_for_a_client() -> None:
    """The reason this block exists, from the production-readiness audit:

    `freedom` dials from the VPN host, so before this rule a client's traffic
    could address the control-plane API and admin panel on loopback, the
    Docker networks PostgreSQL and Redis sit on, the cloud metadata service,
    and Xray's own HandlerService -- which can add users and inbounds and has
    no authentication of its own.
    """

    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(clients=(CLIENT_A,)),
            (XHTTP_PROFILE,),
            tls_cert_file=None,
            tls_key_file=None,
        )
    )

    tags = {outbound["tag"]: outbound["protocol"] for outbound in config["outbounds"]}
    assert tags == {"internet": "freedom", "blocked": "blackhole"}
    # The first outbound is Xray's default route for anything no rule matched,
    # so the real one has to stay first.
    assert config["outbounds"][0]["tag"] == "internet"

    rules = config["routing"]["rules"]
    # The stats rule stays first: it matches by inbound tag, and a later rule
    # matching the API's own loopback address would otherwise swallow it.
    assert rules[0]["inboundTag"] == ["nebula-stats-api"]
    blocked = next(rule for rule in rules if rule.get("outboundTag") == "blocked")
    for destination in ("127.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16", "10.0.0.0/8", "::1/128"):
        assert destination in blocked["ip"]


def test_a_hostname_pointing_at_a_local_address_is_resolved_before_it_is_routed() -> None:
    """A rule carrying only addresses cannot match a request that names a
    host, so `internal.example.com` resolving to 127.0.0.1 would otherwise be
    dialled without ever being compared to the blocked ranges."""

    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(), (XHTTP_PROFILE,), tls_cert_file=None, tls_key_file=None
        )
    )

    assert config["routing"]["domainStrategy"] == "IPIfNonMatch"
    # Resolving has to work without loopback: the firewall layer refuses this
    # service systemd-resolved at 127.0.0.53.
    assert config["dns"]["servers"] and not any(
        server.startswith("127.") for server in config["dns"]["servers"]
    )


def test_localhost_is_refused_by_name_and_never_resolved_by_the_host() -> None:
    """`localhost` has no public answer, so the address rule never saw an
    address for it, and `freedom` asked the host's resolver -- which says
    127.0.0.1. Measured on the production Xray (26.3.27, 2026-10-15): a
    client reached a loopback-only port by that name."""

    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(), (XHTTP_PROFILE,), tls_cert_file=None, tls_key_file=None
        )
    )

    internet = config["outbounds"][0]
    assert internet["tag"] == "internet"
    # IPv4 only: `UseIP` mixes families per connection, and YouTube's
    # streams, tied to the address that asked, would not play.
    assert internet["settings"]["domainStrategy"] == "UseIPv4"
    by_name = [rule for rule in config["routing"]["rules"] if "domain" in rule]
    assert by_name == [
        {
            "type": "field",
            "domain": ["full:localhost", "domain:localhost"],
            "outboundTag": "blocked",
        }
    ]


def test_dns_redirect_sends_only_the_dns_address_to_the_resolver_before_the_block() -> None:
    # Nebula's own resolver (roadmap 26): the clients' reserved DNS address,
    # port 53 only, goes to this host's resolver. It has to come before the
    # rule blocking loopback, or the block would swallow it.
    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(),
            (XHTTP_PROFILE,),
            tls_cert_file=None,
            tls_key_file=None,
            dns_redirect=("198.18.0.53", "127.0.0.1:5354"),
        )
    )
    dns = [o for o in config["outbounds"] if o["tag"] == "nebula-dns"]
    assert dns == [
        {"tag": "nebula-dns", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:5354"}}
    ]
    tags = [r["outboundTag"] for r in config["routing"]["rules"]]
    assert tags.index("nebula-dns") < tags.index("blocked")
    rule = config["routing"]["rules"][tags.index("nebula-dns")]
    assert rule["ip"] == ["198.18.0.53"]
    assert rule["port"] == "53"


def test_no_dns_redirect_leaves_the_config_as_it_was() -> None:
    config = json.loads(
        render_xray_server_config(
            DesiredXrayState(), (XHTTP_PROFILE,), tls_cert_file=None, tls_key_file=None
        )
    )
    assert all(o["tag"] != "nebula-dns" for o in config["outbounds"])
    assert all(r["outboundTag"] != "nebula-dns" for r in config["routing"]["rules"])
