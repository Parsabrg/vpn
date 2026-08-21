"""FastAPI application factory and process entry point."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Literal, cast

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel, ConfigDict
from redis.asyncio import Redis

from nebula_api import __version__
from nebula_api.accounts.email_outbox import EmailOutboxRedisClient
from nebula_api.accounts.routes import admin_router as account_request_admin_router
from nebula_api.accounts.routes import router as account_request_router
from nebula_api.accounts.service import AccountRequestService
from nebula_api.agent_client.client import AgentClient
from nebula_api.audit.routes import router as audit_log_router
from nebula_api.audit.service import AuditLogService
from nebula_api.auth.admin_routes import router as admin_auth_router
from nebula_api.auth.admin_service import AdminAuthService
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.key_material import load_auth_key_material
from nebula_api.auth.redis_state import RedisAuthState, RedisClient
from nebula_api.auth.user_routes import router as user_auth_router
from nebula_api.auth.user_service import PasswordResetDelivery, UserAuthService
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.db.schema import schema_is_current
from nebula_api.devices.routes import router as devices_router
from nebula_api.email_deliveries.routes import router as email_delivery_router
from nebula_api.email_deliveries.service import EmailDeliveryService
from nebula_api.provisioning.service import ProvisioningService
from nebula_api.request_limits import RequestBodyLimitMiddleware
from nebula_api.servers.routes import router as server_discovery_router
from nebula_api.servers.service import ServerDiscoveryService
from nebula_api.settings import Settings, get_settings
from nebula_api.topology_admin.routes import router as topology_admin_router
from nebula_api.topology_admin.service import TopologyAdminService
from nebula_api.user_management.routes import router as user_management_router
from nebula_api.user_management.service import UserManagementService

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
    user_auth_service: UserAuthService | None = None,
    admin_auth_service: AdminAuthService | None = None,
    account_request_service: AccountRequestService | None = None,
    audit_log_service: AuditLogService | None = None,
    email_delivery_service: EmailDeliveryService | None = None,
    topology_admin_service: TopologyAdminService | None = None,
    user_management_service: UserManagementService | None = None,
    provisioning_service: ProvisioningService | None = None,
    server_discovery_service: ServerDiscoveryService | None = None,
    password_reset_delivery: PasswordResetDelivery | None = None,
) -> FastAPI:
    """Create an API instance with startup and database-gated readiness."""

    runtime_settings = settings or get_settings()
    database_engine = None
    redis_client: Redis | None = None
    effective_user_auth_service = user_auth_service
    effective_admin_auth_service = admin_auth_service
    effective_account_request_service = account_request_service
    effective_audit_log_service = audit_log_service
    effective_email_delivery_service = email_delivery_service
    effective_topology_admin_service = topology_admin_service
    effective_user_management_service = user_management_service
    effective_provisioning_service = provisioning_service
    effective_server_discovery_service = server_discovery_service
    effective_readiness_check: ReadinessCheck

    if readiness_check is None:
        database_engine = create_database_engine(
            runtime_settings.database_url.get_secret_value(),
            connect_timeout_seconds=runtime_settings.database_connect_timeout_seconds,
            statement_timeout_ms=runtime_settings.database_statement_timeout_ms,
        )

        redis_client = Redis.from_url(runtime_settings.redis_url.get_secret_value())
        if effective_user_auth_service is None:
            key_material = load_auth_key_material(runtime_settings)
            redis_auth_state = RedisAuthState(
                cast(RedisClient, redis_client),
                key_ring=key_material.token_peppers,
                current_key_version=runtime_settings.token_key_version,
            )
            effective_user_auth_service = UserAuthService(
                create_session_factory(database_engine),
                redis_auth_state,
                key_material,
                runtime_settings,
            )
            if effective_admin_auth_service is None:
                effective_admin_auth_service = AdminAuthService(
                    create_session_factory(database_engine),
                    redis_auth_state,
                    key_material,
                    runtime_settings,
                )
            if effective_account_request_service is None:
                effective_account_request_service = AccountRequestService(
                    create_session_factory(database_engine),
                    redis_auth_state,
                    cast(EmailOutboxRedisClient, redis_client),
                    key_material,
                    runtime_settings,
                )
            if effective_user_management_service is None:
                effective_user_management_service = UserManagementService(
                    create_session_factory(database_engine),
                    redis_auth_state,
                    runtime_settings,
                )
            if effective_provisioning_service is None:
                effective_provisioning_service = ProvisioningService(
                    create_session_factory(database_engine),
                    redis_auth_state,
                    runtime_settings,
                    lambda agent_host, agent_port: AgentClient(
                        agent_host=agent_host, agent_port=agent_port, settings=runtime_settings
                    ),
                )
        if effective_audit_log_service is None:
            effective_audit_log_service = AuditLogService(create_session_factory(database_engine))
        if effective_email_delivery_service is None:
            effective_email_delivery_service = EmailDeliveryService(
                create_session_factory(database_engine)
            )
        if effective_topology_admin_service is None:
            effective_topology_admin_service = TopologyAdminService(
                create_session_factory(database_engine)
            )
        if effective_server_discovery_service is None:
            effective_server_discovery_service = ServerDiscoveryService(
                create_session_factory(database_engine)
            )

        async def database_and_redis_readiness_check() -> bool:
            try:
                database_ready, redis_ready = await asyncio.gather(
                    schema_is_current(database_engine),
                    redis_client.ping(),
                )
            except Exception:
                return False
            return database_ready and bool(redis_ready)

        effective_readiness_check = database_and_redis_readiness_check
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
            if redis_client is not None:
                await redis_client.aclose()

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
    application.state.redis_client = redis_client
    application.state.user_auth_service = effective_user_auth_service
    application.state.admin_auth_service = effective_admin_auth_service
    application.state.account_request_service = effective_account_request_service
    application.state.audit_log_service = effective_audit_log_service
    application.state.email_delivery_service = effective_email_delivery_service
    application.state.topology_admin_service = effective_topology_admin_service
    application.state.user_management_service = effective_user_management_service
    application.state.provisioning_service = effective_provisioning_service
    application.state.server_discovery_service = effective_server_discovery_service
    application.state.password_reset_delivery = password_reset_delivery
    install_auth_http_safeguards(application, runtime_settings)
    application.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=runtime_settings.max_request_bytes,
    )
    application.include_router(user_auth_router)
    application.include_router(admin_auth_router)
    application.include_router(account_request_router)
    application.include_router(account_request_admin_router)
    application.include_router(audit_log_router)
    application.include_router(email_delivery_router)
    application.include_router(topology_admin_router)
    application.include_router(user_management_router)
    application.include_router(devices_router)
    application.include_router(server_discovery_router)

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
