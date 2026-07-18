"""Narrow VPN-agent HTTP surface."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel, ConfigDict

from nebula_agent import __version__
from nebula_agent.settings import Settings, get_settings


class ProbeResponse(BaseModel):
    """Non-sensitive agent probe response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok", "ready", "not_ready"]
    service: Literal["nebula-vpn-agent"] = "nebula-vpn-agent"
    version: str = __version__


def create_app(settings_: Settings | None = None) -> FastAPI:
    """Build the agent without any free-form command or configuration routes."""

    runtime_settings = settings_ or get_settings()

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
