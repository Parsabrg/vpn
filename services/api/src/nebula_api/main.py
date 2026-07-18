"""FastAPI application factory and process entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel, ConfigDict

from nebula_api import __version__
from nebula_api.settings import Settings, get_settings


class ProbeResponse(BaseModel):
    """Non-sensitive health response shared by orchestration probes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok", "ready", "not_ready"]
    service: Literal["nebula-api"] = "nebula-api"
    version: str = __version__


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create an API instance with startup-gated readiness."""

    runtime_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.ready = True
        yield
        app.state.ready = False

    application = FastAPI(
        title="Nebula API",
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
        return ProbeResponse(status="ok", service="nebula-api", version=__version__)

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
