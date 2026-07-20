"""FastAPI application factory and process entry point."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel, ConfigDict

from nebula_api import __version__
from nebula_api.db.engine import create_database_engine
from nebula_api.db.schema import schema_is_current
from nebula_api.settings import Settings, get_settings

ReadinessCheck = Callable[[], Awaitable[bool]]


class ProbeResponse(BaseModel):
    """Non-sensitive health response shared by orchestration probes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok", "ready", "not_ready"]
    service: Literal["nebula-api"] = "nebula-api"
    version: str = __version__


def create_app(
    settings: Settings | None = None,
    *,
    readiness_check: ReadinessCheck | None = None,
) -> FastAPI:
    """Create an API instance with startup and database-gated readiness."""

    runtime_settings = settings or get_settings()
    database_engine = None
    effective_readiness_check: ReadinessCheck

    if readiness_check is None:
        database_engine = create_database_engine(
            runtime_settings.database_url.get_secret_value(),
            connect_timeout_seconds=runtime_settings.database_connect_timeout_seconds,
            statement_timeout_ms=runtime_settings.database_statement_timeout_ms,
        )

        async def database_readiness_check() -> bool:
            return await schema_is_current(database_engine)

        effective_readiness_check = database_readiness_check
    else:
        effective_readiness_check = readiness_check

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.ready = True
        try:
            yield
        finally:
            app.state.ready = False
            if database_engine is not None:
                await database_engine.dispose()

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
    application.state.database_engine = database_engine

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
        database_ready = False
        if request.app.state.ready:
            try:
                async with asyncio.timeout(runtime_settings.readiness_timeout_seconds):
                    database_ready = await effective_readiness_check()
            except TimeoutError:
                database_ready = False
        if not request.app.state.ready or not database_ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return ProbeResponse(status="not_ready")
        return ProbeResponse(status="ready")

    return application


app = create_app()
