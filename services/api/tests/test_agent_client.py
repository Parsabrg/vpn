import asyncio
import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from nebula_api.agent_client.client import (
    AgentClient,
    AgentClientError,
    AgentRejected,
    AgentResponseAmbiguous,
    AgentResponseInvalid,
    AgentUnreachable,
)
from nebula_api.agent_client.models import (
    DisableDeviceRequest,
    EnableDeviceRequest,
    HealthRequest,
    ProvisionDeviceRequest,
    ReconcileRequest,
    RevokeDeviceRequest,
)
from nebula_api.settings import Settings

VALID_PUBLIC_KEY = "MjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMj0="


def _provision_request(**overrides: object) -> ProvisionDeviceRequest:
    defaults: dict[str, object] = {
        "idempotency_key": uuid4(),
        "correlation_id": uuid4(),
        "target_kind": "wireguard_peer",
        "target_id": uuid4(),
        "desired_generation": 1,
        "public_key": VALID_PUBLIC_KEY,
        "assigned_address": "10.77.0.2",
    }
    defaults.update(overrides)
    return ProvisionDeviceRequest(**defaults)


def test_constructing_without_a_transport_requires_mtls_settings() -> None:
    with pytest.raises(AgentClientError, match="mTLS"):
        AgentClient(agent_host="vpn1.internal", agent_port=9443, settings=Settings())


def test_constructing_with_mtls_settings_stores_the_configured_paths() -> None:
    client = AgentClient(
        agent_host="vpn1.internal",
        agent_port=9443,
        settings=Settings(
            agent_client_cert_file="/run/secrets/agent_client_cert",
            agent_client_key_file="/run/secrets/agent_client_key",
            agent_trusted_ca_file="/run/secrets/agent_ca",
        ),
    )
    assert client._mtls == (
        str(Path("/run/secrets/agent_client_cert")),
        str(Path("/run/secrets/agent_client_key")),
        str(Path("/run/secrets/agent_ca")),
    )


def test_entering_without_a_transport_or_mtls_settings_raises() -> None:
    async def scenario() -> None:
        client = AgentClient.__new__(AgentClient)
        client._agent_host = "vpn1.internal"
        client._agent_port = 9443
        client._timeout_seconds = 10.0
        client._transport = None
        client._mtls = None
        client._client = None
        with pytest.raises(AgentClientError, match="mTLS"):
            await client.__aenter__()

    asyncio.run(scenario())


def test_a_non_dict_json_body_uses_a_generic_detail() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json=["not", "a", "dict"])

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentRejected) as excinfo:
                await client.provision_device(_provision_request())
        assert excinfo.value.detail == "Request was not accepted"

    asyncio.run(scenario())


def test_pool_timeout_raises_agent_unreachable() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.PoolTimeout("no available connection in the pool")

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentUnreachable):
                await client.provision_device(_provision_request())

    asyncio.run(scenario())


def test_write_error_raises_agent_response_ambiguous() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.WriteError("connection reset while sending the request")

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentResponseAmbiguous):
                await client.provision_device(_provision_request())

    asyncio.run(scenario())


def test_aexit_closes_the_client() -> None:
    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
        )
        async with client:
            assert client._client is not None
        assert client._client is None

    asyncio.run(scenario())


def test_provision_device_sends_the_correct_path_and_body() -> None:
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "state": "active",
                "applied_generation": 1,
                "server_public_key": VALID_PUBLIC_KEY,
                "listen_port": 51820,
                "public_endpoint": "vpn.test:51820",
                "client_dns": "1.1.1.1",
                "client_allowed_ips": "0.0.0.0/0,::/0",
                "persistent_keepalive_seconds": 25,
            },
        )

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        request = _provision_request()
        async with client:
            response = await client.provision_device(request)

        assert response.state == "active"
        assert response.server_public_key == VALID_PUBLIC_KEY
        assert captured["path"] == "/v1/operations/provision-device"
        assert captured["body"]["public_key"] == VALID_PUBLIC_KEY  # type: ignore[index]
        assert captured["body"]["desired_generation"] == 1  # type: ignore[index]

    asyncio.run(scenario())


def test_health_sends_the_correct_path() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/operations/health"
        return httpx.Response(
            200,
            json={
                "state": "healthy",
                "source": "agent",
                "observed_at": "2026-01-01T00:00:00Z",
                "agent_version": "0.1.0",
                "interface_up": True,
                "peer_count": 3,
            },
        )

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            response = await client.health(HealthRequest(correlation_id=uuid4()))
        assert response.peer_count == 3

    asyncio.run(scenario())


def test_reconcile_sends_the_correct_path() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/operations/reconcile"
        return httpx.Response(200, json={"outcome": "in_sync", "observed_generation": 1})

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        request = ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=VALID_PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=1,
        )
        async with client:
            response = await client.reconcile(request)
        assert response.outcome == "in_sync"

    asyncio.run(scenario())


def test_a_4xx_response_raises_agent_rejected_with_the_agents_detail() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": "idempotency_key was already used"})

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentRejected) as excinfo:
                await client.provision_device(_provision_request())
        assert excinfo.value.status_code == 409
        assert excinfo.value.detail == "idempotency_key was already used"

    asyncio.run(scenario())


def test_a_4xx_response_with_a_non_json_body_uses_a_generic_detail() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal server error")

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentRejected) as excinfo:
                await client.provision_device(_provision_request())
        assert excinfo.value.detail == "Request was not accepted"

    asyncio.run(scenario())


def test_a_malformed_2xx_body_raises_agent_response_invalid() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"state": "not-a-real-state"})

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentResponseInvalid):
                await client.provision_device(_provision_request())

    asyncio.run(scenario())


def test_connect_error_raises_agent_unreachable() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentUnreachable):
                await client.provision_device(_provision_request())

    asyncio.run(scenario())


def test_read_timeout_raises_agent_response_ambiguous() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out waiting for a response")

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentResponseAmbiguous):
                await client.provision_device(_provision_request())

    asyncio.run(scenario())


def test_remote_protocol_error_raises_agent_response_ambiguous() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("connection closed mid-response")

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentResponseAmbiguous):
                await client.provision_device(_provision_request())

    asyncio.run(scenario())


def test_using_the_client_outside_the_context_manager_raises() -> None:
    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
        )
        with pytest.raises(AgentClientError, match="async context manager"):
            await client.health(HealthRequest(correlation_id=uuid4()))

    asyncio.run(scenario())


def test_revoke_device_sends_the_correct_path_and_parses_the_response() -> None:
    """Covered here rather than only through ProvisioningService, whose tests
    use a fake client -- a wrong URL or response model on this path would
    otherwise not surface until a real agent call."""

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/operations/revoke-device"
        return httpx.Response(
            200,
            json={
                "state": "revoked",
                "applied_generation": 2,
                "revoked_at": "2026-01-01T00:00:00Z",
            },
        )

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        request = RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=VALID_PUBLIC_KEY,
            desired_generation=2,
        )
        async with client:
            response = await client.revoke_device(request)
        assert response.state == "revoked"
        assert response.applied_generation == 2

    asyncio.run(scenario())


def test_enable_device_sends_the_correct_path_and_parses_the_response() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/operations/enable-device"
        return httpx.Response(200, json={"state": "enabled", "applied_generation": 3})

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        request = EnableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=VALID_PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=3,
        )
        async with client:
            response = await client.enable_device(request)
        assert response.state == "enabled"
        assert response.applied_generation == 3

    asyncio.run(scenario())


def test_disable_device_sends_the_correct_path_and_parses_the_response() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/operations/disable-device"
        return httpx.Response(200, json={"state": "disabled", "applied_generation": 4})

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        request = DisableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=VALID_PUBLIC_KEY,
            desired_generation=4,
        )
        async with client:
            response = await client.disable_device(request)
        assert response.state == "disabled"

    asyncio.run(scenario())


def test_an_unclassified_request_error_is_treated_as_ambiguous() -> None:
    """The catch-all deliberately errs toward ambiguous: for any transport
    failure not known to have happened before the request was sent, we cannot
    prove the agent did not apply it, so it must not be marked failed."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.LocalProtocolError("malformed request state")

    async def scenario() -> None:
        client = AgentClient(
            agent_host="vpn1.internal",
            agent_port=9443,
            settings=Settings(),
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(AgentResponseAmbiguous):
                await client.provision_device(_provision_request())

    asyncio.run(scenario())
