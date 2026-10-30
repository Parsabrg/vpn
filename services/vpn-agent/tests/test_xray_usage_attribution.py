"""Xray must be able to say whose bytes those were.

Traffic counters are useless for a quota if they only total the server. Xray
keys per-user counters on a client's `email`, and reports nothing per-user
without one, so these tests pin the two things that make attribution possible:
every client carries an email, and the stats service is actually enabled.
"""

import json
from typing import Any

from test_xray_config_store import (
    CLIENT_A,
    CLIENT_B,
    CLIENT_C,
    GRPC_PROFILE,
    XHTTP_PROFILE,
)

from nebula_agent.drivers.xray_config_store import (
    STATS_API_HOST,
    STATS_API_PORT,
    DesiredXrayState,
    client_email,
    render_xray_server_config,
)
from nebula_agent.usage import digest_identity


def _config(**options: Any) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(
        render_xray_server_config(
            DesiredXrayState(clients=(CLIENT_A, CLIENT_B, CLIENT_C)),
            (XHTTP_PROFILE, GRPC_PROFILE),
            tls_cert_file="/cert",
            tls_key_file="/key",
            **options,
        )
    )
    return parsed


def test_every_client_email_is_the_digest_the_usage_report_uses() -> None:
    # The email is the attribution key, and the control plane resolves a
    # counter to a credential by this digest. If the two ever disagree,
    # every byte is attributed to nobody, and nothing fails.
    config = _config()
    for inbound in config["inbounds"]:
        for client in inbound.get("settings", {}).get("clients", []):
            assert client["email"] == digest_identity(client["id"])
            assert client["email"] == client_email(client["id"])


def test_no_email_is_the_credential_itself() -> None:
    # Xray reports emails to anything that can reach its API. For VLESS the
    # UUID is the credential, so an email that was the UUID gave it away.
    config = _config()
    for inbound in config["inbounds"]:
        for client in inbound.get("settings", {}).get("clients", []):
            assert client["id"] not in client["email"]


def test_no_client_is_left_without_an_email() -> None:
    # The failure this prevents is silent: Xray starts happily, serves
    # traffic, and simply reports no per-user counters for that client.
    config = _config()
    emails = [
        client.get("email")
        for inbound in config["inbounds"]
        for client in inbound.get("settings", {}).get("clients", [])
    ]
    assert emails
    assert all(email for email in emails)


def test_user_counters_are_switched_on() -> None:
    # Xray accumulates only what policy asks for; without these two the stats
    # service answers with zeroes.
    config = _config()
    level_zero = config["policy"]["levels"]["0"]
    assert level_zero["statsUserUplink"] is True
    assert level_zero["statsUserDownlink"] is True
    assert config["stats"] == {}


def test_the_stats_service_listens_on_loopback_only() -> None:
    # The stats service has no authentication of its own, so the bind address
    # is the entire access control: anything that can reach it can read every
    # user's totals.
    config = _config()
    api_inbound = next(i for i in config["inbounds"] if i["port"] == STATS_API_PORT)
    assert api_inbound["listen"] == STATS_API_HOST == "127.0.0.1"
    assert config["api"]["services"] == ["StatsService"]


def test_the_api_can_listen_on_a_loopback_address_of_its_own() -> None:
    # So the host can refuse that one address to local users -- the CI
    # runner -- without taking 127.0.0.1 away from them.
    config = _config(api_host="127.25.41.4")
    api_inbound = next(i for i in config["inbounds"] if i["port"] == STATS_API_PORT)
    assert api_inbound["listen"] == "127.25.41.4"
    assert api_inbound["settings"]["address"] == "127.25.41.4"


def test_the_handler_service_is_on_only_for_live_client_updates() -> None:
    # It can add users and whole inbounds. A deployment that restarts to
    # change clients has no use for it and should not be exposing it.
    assert "HandlerService" not in _config()["api"]["services"]
    assert "HandlerService" in _config(live_client_updates=True)["api"]["services"]


def test_api_traffic_is_routed_before_anything_else() -> None:
    # A later rule could otherwise swallow it, and the port would answer
    # nothing while looking correctly configured.
    config = _config()
    first = config["routing"]["rules"][0]
    assert first["inboundTag"] == [config["api"]["tag"]]
    assert first["outboundTag"] == config["api"]["tag"]


def test_profile_inbounds_are_tagged_so_counters_can_be_read_per_transport() -> None:
    config = _config()
    tags = {i["tag"] for i in config["inbounds"]}
    assert {XHTTP_PROFILE.protocol_profile_code, GRPC_PROFILE.protocol_profile_code} <= tags
