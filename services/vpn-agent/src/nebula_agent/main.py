"""Narrow VPN-agent HTTP surface."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel, ConfigDict

from nebula_agent import __version__
from nebula_agent.api.v1 import router as operations_router
from nebula_agent.api.v1_usage import router as usage_router
from nebula_agent.api.v1_xray import router as xray_operations_router
from nebula_agent.driver_factory import build_xray_driver
from nebula_agent.drivers.base import WireGuardDriver
from nebula_agent.drivers.config_store import ConfigStore
from nebula_agent.drivers.errors import DriverError
from nebula_agent.drivers.fake import FakeWireGuardRunner
from nebula_agent.drivers.hysteria_config_store import HYSTERIA_AUTH_PATH, HYSTERIA_AUTH_PORT
from nebula_agent.drivers.wireguard import NativeWireGuardDriver
from nebula_agent.drivers.xray_base import XrayDriver
from nebula_agent.hysteria_auth import HysteriaAuthServer
from nebula_agent.ledger import OperationLedger
from nebula_agent.settings import Settings, get_settings

_LOGGER = logging.getLogger(__name__)


class ProbeResponse(BaseModel):
    """Non-sensitive agent probe response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok", "ready", "not_ready"]
    service: Literal["nebula-vpn-agent"] = "nebula-vpn-agent"
    version: str = __version__


def _build_driver(settings: Settings) -> WireGuardDriver:
    if settings.wg_driver == "fake":
        return FakeWireGuardRunner()
    store = ConfigStore(settings.wg_state_dir, settings.wg_interface)
    return NativeWireGuardDriver(settings, store)


async def _resync_xray_config(xray_driver: XrayDriver) -> None:
    """Re-render the served config on startup, and never fail to start over it.

    A restart is how an operator deploys the agent, so it has to be how a
    change to the rendered config takes effect. But an agent that refuses to
    start has stopped serving provisioning entirely, which is far worse than
    one serving a slightly stale config -- so every failure here is logged and
    swallowed. The driver itself guarantees the transport stays up: it
    validates against a scratch copy before touching the live file, and puts
    back exactly what was being served if a validated config still fails to
    load.
    """

    try:
        if await xray_driver.resync_served_config():
            _LOGGER.info("re-rendered the served Xray config to match this build")
    except Exception:
        _LOGGER.exception("could not re-render the served Xray config; serving the existing one")


async def _start_hysteria_auth(
    settings: Settings, xray_driver: XrayDriver
) -> HysteriaAuthServer | None:
    """Start answering Hysteria2's authentication, if its config asks us.

    Only with live client updates on and Hysteria2 served: that is when the
    rendered config points Hysteria at this listener. Before the re-render,
    so a Hysteria restarted onto that config finds someone answering.

    A listener that cannot start is logged and not fatal. New Hysteria2
    connections are refused until it can, but WireGuard, Xray and
    provisioning carry on, which is better than an agent that does not start.
    """

    if not settings.xray_live_client_updates or settings.hysteria_server_profile() is None:
        return None
    server = HysteriaAuthServer(
        settings.xray_api_host,
        HYSTERIA_AUTH_PORT,
        HYSTERIA_AUTH_PATH,
        xray_driver.authorize_hysteria,
    )
    try:
        await server.start()
    except OSError:
        _LOGGER.exception("could not start the Hysteria2 auth listener")
        return None
    return server


def create_app(
    settings_: Settings | None = None,
    *,
    driver: WireGuardDriver | None = None,
    xray_driver: XrayDriver | None = None,
    ledger: OperationLedger | None = None,
) -> FastAPI:
    """Build the agent without any free-form command or configuration routes.

    The agent serves both protocols from one process: the WireGuard driver
    (unconditional, matches every deployment today) and the Xray driver
    (gated behind `xray_enabled`, defaulting to the capability-free fake
    runner exactly like `wg_driver` does)."""

    runtime_settings = settings_ or get_settings()
    runtime_driver = driver or _build_driver(runtime_settings)
    runtime_xray_driver = xray_driver or build_xray_driver(runtime_settings)
    runtime_ledger = ledger or OperationLedger(
        runtime_settings.operation_ledger_file,
        runtime_settings.operation_ledger_max_entries,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Before serving, not after: provisioning against a config this build
        # is about to rewrite would apply a delta on top of the old shape and
        # then have it replaced underneath.
        hysteria_auth = await _start_hysteria_auth(runtime_settings, runtime_xray_driver)
        await _resync_xray_config(runtime_xray_driver)
        app.state.ready = True
        try:
            yield
        finally:
            app.state.ready = False
            if hysteria_auth is not None:
                await hysteria_auth.close()

    application = FastAPI(
        title="Nebula VPN agent",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.ready = False
    application.state.settings = runtime_settings
    application.state.driver = runtime_driver
    application.state.xray_driver = runtime_xray_driver
    application.state.ledger = runtime_ledger

    @application.exception_handler(DriverError)
    async def _handle_driver_error(_request: Request, _error: DriverError) -> Response:
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    application.include_router(operations_router)
    application.include_router(xray_operations_router)
    application.include_router(usage_router)

    @application.get("/healthz", response_model=ProbeResponse, tags=["probes"])
    async def health() -> ProbeResponse:
        return ProbeResponse(status="ok")

    @application.get(
        "/readyz",
        response_model=ProbeResponse,
        responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ProbeResponse}},
        tags=["probes"],
    )
    async def readiness(request: Request, response: Response) -> ProbeResponse:
        if not request.app.state.ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return ProbeResponse(status="not_ready")
        return ProbeResponse(status="ready")

    return application


app = create_app()
