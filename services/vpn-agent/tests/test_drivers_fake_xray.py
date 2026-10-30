from uuid import uuid4

import pytest

from nebula_agent.drivers.fake import FakeXrayRunner
from nebula_agent.drivers.xray_base import (
    ExpectedXrayClient,
    ProvisionXrayClientRequest,
    PruneXrayClientsRequest,
    RevokeXrayClientRequest,
    XrayHealthRequest,
)
from nebula_agent.drivers.xray_config_store import XrayInboundProfile

CLIENT_UUID = uuid4()
OTHER_CLIENT_UUID = uuid4()


def _provision_request(**overrides: object) -> ProvisionXrayClientRequest:
    defaults: dict[str, object] = {
        "idempotency_key": uuid4(),
        "correlation_id": uuid4(),
        "target_kind": "xray_client",
        "target_id": uuid4(),
        "desired_generation": 0,
        "client_uuid": CLIENT_UUID,
        "protocol_profile_code": "vless-xhttp-tls",
    }
    defaults.update(overrides)
    return ProvisionXrayClientRequest(**defaults)


@pytest.mark.anyio
async def test_provision_client_activates_a_client() -> None:
    driver = FakeXrayRunner()
    response = await driver.provision_client(_provision_request())

    assert response.state == "active"
    assert response.applied_generation == 0
    assert response.error_code is None
    # The default fake profile mirrors XHTTP: nginx (not Xray) terminates
    # TLS, so the inbound's own security is "none".
    assert response.transport_security == "none"


@pytest.mark.anyio
async def test_applied_generation_echoes_the_requests_desired_generation() -> None:
    driver = FakeXrayRunner()
    response = await driver.provision_client(_provision_request(desired_generation=7))
    assert response.applied_generation == 7


@pytest.mark.anyio
async def test_failed_apply_reports_the_clients_last_successfully_applied_generation() -> None:
    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request(desired_generation=3))

    driver.fail_next_apply()
    response = await driver.provision_client(_provision_request(desired_generation=4))

    assert response.state == "failed"
    assert response.applied_generation == 3


@pytest.mark.anyio
async def test_failed_apply_for_a_never_applied_client_reports_generation_zero() -> None:
    driver = FakeXrayRunner()
    driver.fail_next_apply()

    response = await driver.provision_client(_provision_request(desired_generation=4))

    assert response.state == "failed"
    assert response.applied_generation == 0


@pytest.mark.anyio
async def test_provision_client_is_reflected_in_health_client_count() -> None:
    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request())

    health = await driver.health(XrayHealthRequest(correlation_id=uuid4()))
    assert health.client_count == 1
    assert health.state == "healthy"
    assert health.listener_up is True


@pytest.mark.anyio
async def test_provisioning_the_same_uuid_twice_replaces_not_duplicates() -> None:
    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request())
    await driver.provision_client(_provision_request(desired_generation=1))

    health = await driver.health(XrayHealthRequest(correlation_id=uuid4()))
    assert health.client_count == 1


@pytest.mark.anyio
async def test_revoke_client_removes_the_client() -> None:
    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request())

    response = await driver.revoke_client(
        RevokeXrayClientRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="xray_client",
            target_id=uuid4(),
            client_uuid=CLIENT_UUID,
            protocol_profile_code="vless-xhttp-tls",
            desired_generation=1,
        )
    )
    assert response.state == "revoked"

    health = await driver.health(XrayHealthRequest(correlation_id=uuid4()))
    assert health.client_count == 0


@pytest.mark.anyio
async def test_revoking_an_unknown_client_still_succeeds() -> None:
    driver = FakeXrayRunner()
    response = await driver.revoke_client(
        RevokeXrayClientRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="xray_client",
            target_id=uuid4(),
            client_uuid=CLIENT_UUID,
            protocol_profile_code="vless-xhttp-tls",
            desired_generation=0,
        )
    )
    assert response.state == "revoked"


@pytest.mark.anyio
async def test_injected_failure_is_reported_without_mutating_state() -> None:
    driver = FakeXrayRunner()
    driver.fail_next_apply()

    response = await driver.provision_client(_provision_request())
    assert response.state == "failed"
    assert response.error_code == "apply_failed"

    health = await driver.health(XrayHealthRequest(correlation_id=uuid4()))
    assert health.client_count == 0


@pytest.mark.anyio
async def test_injected_failure_is_reported_on_revoke_client() -> None:
    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request())
    driver.fail_next_apply()

    response = await driver.revoke_client(
        RevokeXrayClientRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="xray_client",
            target_id=uuid4(),
            client_uuid=CLIENT_UUID,
            protocol_profile_code="vless-xhttp-tls",
            desired_generation=1,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"
    assert (await driver.health(XrayHealthRequest(correlation_id=uuid4()))).client_count == 1


@pytest.mark.anyio
async def test_failure_only_affects_the_next_call() -> None:
    driver = FakeXrayRunner()
    driver.fail_next_apply()
    await driver.provision_client(_provision_request())

    response = await driver.provision_client(_provision_request(client_uuid=OTHER_CLIENT_UUID))
    assert response.state == "active"


@pytest.mark.anyio
async def test_provision_client_response_carries_the_configured_server_identity() -> None:
    profile = XrayInboundProfile(
        protocol_profile_code="vless-xhttp-tls",
        transport="xhttp",
        listen="127.0.0.1",
        port=8445,
        security="none",
        xhttp_path="/xhttp",
    )
    driver = FakeXrayRunner(
        server_address="vpn.example.test", sni="vpn.example.test", profiles=(profile,)
    )
    response = await driver.provision_client(_provision_request())

    assert response.server_address == "vpn.example.test"
    assert response.port == 8445
    assert response.sni == "vpn.example.test"


# --- prune_clients ----------------------------------------------------------
#
# The fake serves development and CI, so a prune that behaves differently here
# than on the native driver makes both harder to trust. These pin the two
# outcomes that matter, and the no-op case in particular: it is what stops a
# routine sweep from applying on a healthy server.


def _prune_request(*keep: object) -> PruneXrayClientsRequest:
    return PruneXrayClientsRequest(
        correlation_id=uuid4(),
        expected=tuple(
            ExpectedXrayClient(client_uuid=c, protocol_profile_code="vless-xhttp-tls") for c in keep
        ),
    )


@pytest.mark.anyio
async def test_prune_drops_clients_absent_from_the_expected_set() -> None:
    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request())
    await driver.provision_client(_provision_request(client_uuid=OTHER_CLIENT_UUID))

    response = await driver.prune_clients(_prune_request(CLIENT_UUID))

    assert response.state == "pruned"
    assert response.removed == 1
    assert response.kept == 1


@pytest.mark.anyio
async def test_prune_with_nothing_to_remove_is_a_no_op() -> None:
    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request())

    response = await driver.prune_clients(_prune_request(CLIENT_UUID))

    assert response.state == "pruned"
    assert response.removed == 0
    assert response.kept == 1


@pytest.mark.anyio
async def test_prune_reports_apply_failed_without_dropping_anything() -> None:
    """An injected failure must leave the client set intact. Reporting removed
    clients that are still being served would tell the API to forget rows whose
    credentials still work."""

    driver = FakeXrayRunner()
    await driver.provision_client(_provision_request())
    await driver.provision_client(_provision_request(client_uuid=OTHER_CLIENT_UUID))
    driver.fail_next_apply()

    response = await driver.prune_clients(_prune_request(CLIENT_UUID))

    assert response.state == "failed"
    assert response.error_code == "apply_failed"
    assert response.removed == 0
    assert response.kept == 2
