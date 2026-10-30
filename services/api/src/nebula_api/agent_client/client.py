"""mTLS HTTP client for one VPN agent's typed operation API.

A server row identifies one agent (docs/architecture.md: "For one VPS, a
server row identifies the local agent"), so a client is always constructed
per-server from that row's agent_host/agent_port -- never a single global
base URL. `AgentClient.__init__` itself does no I/O; entering the context
manager builds the SSL context from the configured cert/key/CA files
(raising immediately if they don't exist), but the actual TCP connection and
TLS handshake to the agent stay lazy until the first request.
"""

import ssl
from collections.abc import Callable
from types import TracebackType
from typing import Self

import httpx
from pydantic import BaseModel

from nebula_api.agent_client.models import (
    CollectUsageRequest,
    CollectUsageResponse,
    DisableDeviceRequest,
    DisableDeviceResponse,
    EnableDeviceRequest,
    EnableDeviceResponse,
    HealthRequest,
    HealthResponse,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ProvisionXrayClientRequest,
    ProvisionXrayClientResponse,
    PruneXrayClientsRequest,
    PruneXrayClientsResponse,
    ReconcileRequest,
    ReconcileResponse,
    ReconcileXrayClientRequest,
    ReconcileXrayClientResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
    RevokeXrayClientRequest,
    RevokeXrayClientResponse,
    XrayHealthRequest,
    XrayHealthResponse,
)
from nebula_api.settings import Settings

_GENERIC_DETAIL = "Request was not accepted"


class AgentClientError(Exception):
    """Base class for all agent-client failures."""


class AgentUnreachable(AgentClientError):
    """The request never reached the agent (connection refused, DNS failure,
    connect timeout) -- safe to treat the operation as not applied."""


class AgentResponseAmbiguous(AgentClientError):
    """The request may have reached the agent but the response was lost
    (read timeout, dropped connection) -- the operation's actual outcome is
    unknown and must not be guessed; defer to reconciliation."""


class AgentRejected(AgentClientError):
    """The agent returned a clean 4xx/5xx -- safe to treat as a definite
    outcome, using the agent's own error detail."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"agent rejected the request ({status_code}): {detail}")
        self.status_code = status_code
        self.detail = detail


class AgentResponseInvalid(AgentClientError):
    """The agent returned 2xx but the body failed local model validation."""


def _agent_base_url(agent_host: str, agent_port: int) -> str:
    return f"https://{agent_host}:{agent_port}"


def _build_mtls_context(cert_file: str, key_file: str, ca_file: str) -> ssl.SSLContext:
    """The mTLS context for every call to a VPN agent.

    This used to cap at TLS 1.2. uvicorn's asyncio TLS transport -- the agent's
    server -- dropped the connection with no log output when a 1.3 handshake
    was combined with mandatory client-certificate verification and httpcore's
    multi-write request pattern. The cap was a targeted workaround, and it was
    correct at the time: a raw single-shot send and a 1.2-capped client both
    succeeded where 1.3 failed, against the same agent and certs.

    It is gone because the bug is gone. Re-tested against the production agent
    from inside the API container -- same certificates, same uvicorn, httpx
    0.28.1, OpenSSL 3.0.20 -- with a body large enough to force the multi-write
    pattern the failure needed: five of five requests completed at 1.3, and
    five of five at 1.2. Keeping the cap after that would be a permanent
    downgrade maintained out of habit.

    To re-check after upgrading uvicorn or httpx: POST a >32KB body to a path
    the agent does not serve, with and without a maximum_version, and confirm
    both return 404 rather than hanging. A path that 404s is deliberate -- it
    exercises the whole channel while provisioning nothing.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Explicit rather than inherited: this channel carries provisioning
    # commands, and the default floor is a property of whichever Python and
    # OpenSSL the image happens to ship.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(ca_file)
    context.load_cert_chain(cert_file, key_file)
    return context


def _extract_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return _GENERIC_DETAIL
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str):
            return detail
    return _GENERIC_DETAIL


class AgentClient:
    """One VPN agent's typed operation API, over mutual TLS."""

    def __init__(
        self,
        *,
        agent_host: str,
        agent_port: int,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """`transport` is a test-only hook (e.g. httpx.MockTransport) that
        bypasses the mTLS cert/key/CA requirement entirely -- production
        callers never pass it."""

        self._mtls: tuple[str, str, str] | None = None
        if transport is None:
            # Existence rather than configuration: these resolve to a default
            # inside the state directory that `nebula-api initialize` fills
            # in, so an unset path is normal and a missing file is the real
            # fault -- and one worth naming here, because the alternative is
            # an SSL error from three layers down that says nothing about
            # which end of the deployment was never initialised.
            material = (
                settings.resolved_agent_client_cert_file,
                settings.resolved_agent_client_key_file,
                settings.resolved_agent_trusted_ca_file,
            )
            absent = [str(path) for path in material if not path.exists()]
            if absent:
                raise AgentClientError(
                    "the control plane has no client certificate for the agent link ("
                    + ", ".join(absent)
                    + " missing); run `nebula-api initialize`"
                )
            self._mtls = (str(material[0]), str(material[1]), str(material[2]))
        self._agent_host = agent_host
        self._agent_port = agent_port
        self._timeout_seconds = settings.agent_request_timeout_seconds
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Self:
        base_url = _agent_base_url(self._agent_host, self._agent_port)
        if self._transport is not None:
            self._client = httpx.AsyncClient(
                base_url=base_url, transport=self._transport, timeout=self._timeout_seconds
            )
        elif self._mtls is not None:
            cert_file, key_file, ca_file = self._mtls
            self._client = httpx.AsyncClient(
                base_url=base_url,
                verify=_build_mtls_context(cert_file, key_file, ca_file),
                timeout=self._timeout_seconds,
            )
        else:
            raise AgentClientError("agent mTLS client certificate/key/CA are not configured")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _post(self, path: str, request: BaseModel) -> httpx.Response:
        if self._client is None:
            raise AgentClientError("AgentClient must be used as an async context manager")
        payload = request.model_dump(mode="json")
        try:
            return await self._client.post(path, json=payload)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as error:
            raise AgentUnreachable(str(error)) from error
        except (
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.WriteError,
            httpx.RemoteProtocolError,
        ) as error:
            raise AgentResponseAmbiguous(str(error)) from error
        except httpx.RequestError as error:
            # Anything else (local protocol error, decoding error, ...): we
            # cannot be certain the request never reached the agent, so err
            # on the side of ambiguous rather than silently marking failed.
            raise AgentResponseAmbiguous(str(error)) from error

    async def _call[ResponseT: BaseModel](
        self, path: str, request: BaseModel, response_model: type[ResponseT]
    ) -> ResponseT:
        response = await self._post(path, request)
        if response.status_code >= 400:
            raise AgentRejected(response.status_code, _extract_detail(response))
        try:
            return response_model.model_validate(response.json())
        except (ValueError, TypeError) as error:
            raise AgentResponseInvalid(str(error)) from error

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        return await self._call("/v1/operations/provision-device", request, ProvisionDeviceResponse)

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        return await self._call("/v1/operations/revoke-device", request, RevokeDeviceResponse)

    async def enable_device(self, request: EnableDeviceRequest) -> EnableDeviceResponse:
        return await self._call("/v1/operations/enable-device", request, EnableDeviceResponse)

    async def disable_device(self, request: DisableDeviceRequest) -> DisableDeviceResponse:
        return await self._call("/v1/operations/disable-device", request, DisableDeviceResponse)

    async def health(self, request: HealthRequest) -> HealthResponse:
        return await self._call("/v1/operations/health", request, HealthResponse)

    async def reconcile(self, request: ReconcileRequest) -> ReconcileResponse:
        return await self._call("/v1/operations/reconcile", request, ReconcileResponse)

    async def collect_usage(self, request: CollectUsageRequest) -> CollectUsageResponse:
        return await self._call("/v1/usage/collect", request, CollectUsageResponse)

    async def provision_xray_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        return await self._call(
            "/v1/xray-operations/provision-client", request, ProvisionXrayClientResponse
        )

    async def revoke_xray_client(
        self, request: RevokeXrayClientRequest
    ) -> RevokeXrayClientResponse:
        return await self._call(
            "/v1/xray-operations/revoke-client", request, RevokeXrayClientResponse
        )

    async def reconcile_xray_client(
        self, request: ReconcileXrayClientRequest
    ) -> ReconcileXrayClientResponse:
        return await self._call(
            "/v1/xray-operations/reconcile-client", request, ReconcileXrayClientResponse
        )

    async def prune_xray_clients(
        self, request: PruneXrayClientsRequest
    ) -> PruneXrayClientsResponse:
        return await self._call(
            "/v1/xray-operations/prune-clients", request, PruneXrayClientsResponse
        )

    async def xray_health(self, request: XrayHealthRequest) -> XrayHealthResponse:
        return await self._call("/v1/xray-operations/health", request, XrayHealthResponse)


AgentClientBuilder = Callable[[str, int], AgentClient]
"""Builds an AgentClient from (agent_host, agent_port) -- the injection point
provisioning/service.py uses so tests can supply a fake."""
