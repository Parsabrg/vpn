"""Narrow VPN-agent HTTP surface."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel, ConfigDict

from nebula_agent import __version__
from nebula_agent.api.v1 import router as operations_router
from nebula_agent.drivers.base import WireGuardDriver
from nebula_agent.drivers.errors import DriverError
from nebula_agent.drivers.fake import FakeWireGuardRunner
from nebula_agent.ledger import OperationLedger
from nebula_agent.settings import Settings, get_settings


class ProbeResponse(BaseModel):
    """Non-sensitive agent probe response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok", "ready", "not_ready"]
    service: Literal["nebula-vpn-agent"] = "nebula-vpn-agent"
    version: str = __version__


def _build_driver(settings: Settings) -> WireGuardDriver:
    if settings.wg_driver == "fake":
        return FakeWireGuardRunner()
    # The native driver ships in milestone 5; selecting it before then is a
    # deployment misconfiguration, not a request the agent can serve.
    raise NotImplementedError("the native WireGuard driver is not available yet")


def create_app(
    settings_: Settings | None = None,
    *,
    driver: WireGuardDriver | None = None,
    ledger: OperationLedger | None = None,
) -> FastAPI:
    """Build the agent without any free-form command or configuration routes."""

    runtime_settings = settings_ or get_settings()
    runtime_driver = driver or _build_driver(runtime_settings)
    runtime_ledger = ledger or OperationLedger(
        runtime_settings.operation_ledger_file,
        runtime_settings.operation_ledger_max_entries,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.ready = True
        yield
        app.state.ready = False

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
    application.state.ledger = runtime_ledger

    @application.exception_handler(DriverError)
    async def _handle_driver_error(_request: Request, _error: DriverError) -> Response:
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    application.include_router(operations_router)

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
