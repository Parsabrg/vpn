from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.models.types import AdminRole
from nebula_api.settings import Settings
from nebula_api.topology_admin.routes import router
from nebula_api.topology_admin.service import (
    ProtocolEntry,
    ProtocolProfileEntry,
    ReconciliationHistoryEntry,
    ReconciliationHistoryPage,
    TopologyAdminService,
    TrafficSummaryEntry,
    VpnServerEntry,
    VpnServerHealthEntry,
    VpnServerReconciliationEntry,
    VpnServerXrayHealthEntry,
)

ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.AUDITOR) -> None:
        self.role = role

    async def principal(self, _session_token: str) -> AdminPrincipal:
        return AdminPrincipal(ADMIN_ID, SESSION_ID, self.role, False, "totp")


class FakeTopologyAdminService:
    def __init__(self) -> None:
        self.protocols: list[ProtocolEntry] = []
        self.profiles: list[ProtocolProfileEntry] = []
        self.servers: list[VpnServerEntry] = []
        self.health: list[VpnServerHealthEntry] = []
        self.traffic: list[TrafficSummaryEntry] = []
        self.xray_health: list[VpnServerXrayHealthEntry] = []
        self.reconciliation: list[VpnServerReconciliationEntry] = []
        self.history = ReconciliationHistoryPage([], 0)
        self.history_query: dict[str, object] = {}

    async def list_protocols(self) -> list[ProtocolEntry]:
        return self.protocols

    async def list_protocol_profiles(self) -> list[ProtocolProfileEntry]:
        return self.profiles

    async def list_vpn_servers(self) -> list[VpnServerEntry]:
        return self.servers

    async def get_vpn_server_health(self) -> list[VpnServerHealthEntry]:
        return self.health

    async def get_traffic_summary(self) -> list[TrafficSummaryEntry]:
        return self.traffic

    async def get_vpn_server_xray_health(self) -> list[VpnServerXrayHealthEntry]:
        return self.xray_health

    async def get_vpn_server_reconciliation(self) -> list[VpnServerReconciliationEntry]:
        return self.reconciliation

    async def list_reconciliation_history(self, **query: object) -> ReconciliationHistoryPage:
        self.history_query = query
        return self.history


def make_client(topology_service: FakeTopologyAdminService | None = None) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.topology_admin_service = cast(
        TopologyAdminService, topology_service or FakeTopologyAdminService()
    )
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def _authenticated(client: TestClient) -> None:
    client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")


def test_traffic_summary_requires_session() -> None:
    with make_client() as client:
        assert client.get("/v1/admin/traffic-summary").status_code == 401


def test_traffic_summary_returns_only_aggregate_evidence_without_losing_integer_precision() -> None:
    service = FakeTopologyAdminService()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service.traffic = [
        TrafficSummaryEntry("xray", 2**63 + 1, 2**63 + 3, now),
        TrafficSummaryEntry("hysteria2", 0, 0, None),
    ]
    with make_client(service) as client:
        _authenticated(client)
        response = client.get("/v1/admin/traffic-summary")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "items": [
            {
                "protocol": "xray",
                "rx_bytes": str(2**63 + 1),
                "tx_bytes": str(2**63 + 3),
                "total_bytes": str(2**64 + 4),
                "newest_collected_at": "2026-01-01T00:00:00Z",
            },
            {
                "protocol": "hysteria2",
                "rx_bytes": "0",
                "tx_bytes": "0",
                "total_bytes": "0",
                "newest_collected_at": None,
            },
        ]
    }


def test_traffic_summary_empty_and_unavailable_data() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/traffic-summary")
        assert response.status_code == 200
        assert response.json() == {"items": []}
        assert response.headers["cache-control"] == "no-store"
        cast(FastAPI, client.app).state.topology_admin_service = None
        assert client.get("/v1/admin/traffic-summary").status_code == 503


def test_xray_health_requires_session() -> None:
    with make_client() as client:
        assert client.get("/v1/admin/vpn-servers/xray-health").status_code == 401


def test_xray_health_maps_safe_evidence_with_no_store() -> None:
    service = FakeTopologyAdminService()
    entry = VpnServerXrayHealthEntry(
        uuid4(),
        "ams-1",
        "unreachable",
        datetime(2026, 1, 1, tzinfo=UTC),
        None,
        None,
        None,
        "agent_response_invalid",
    )
    service.xray_health = [entry]
    with make_client(service) as client:
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers/xray-health")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "items": [
            {
                "server_id": str(entry.server_id),
                "code": "ams-1",
                "state": "unreachable",
                "observed_at": "2026-01-01T00:00:00Z",
                "latency_ms": None,
                "agent_version": None,
                "listener_up": None,
                "error_code": "agent_response_invalid",
            }
        ]
    }


def test_xray_health_empty_and_unavailable_inventory() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers/xray-health")
        assert response.json() == {"items": []}
        assert response.headers["cache-control"] == "no-store"
        cast(FastAPI, client.app).state.topology_admin_service = None
        assert client.get("/v1/admin/vpn-servers/xray-health").status_code == 503


def test_reconciliation_history_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/reconciliation-history")
    assert response.status_code == 401


@pytest.mark.parametrize(
    "query",
    [
        "server_id=not-a-uuid",
        "target_id=not-a-uuid",
        "outcome=unsupported",
        "limit=101",
        "limit=0",
        "offset=-1",
    ],
)
def test_reconciliation_history_rejects_invalid_filters_and_page_bounds(query: str) -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get(f"/v1/admin/reconciliation-history?{query}")
    assert response.status_code == 422


def test_reconciliation_history_maps_only_safe_metadata_and_passes_filters() -> None:
    service = FakeTopologyAdminService()
    entry = ReconciliationHistoryEntry(
        uuid4(),
        uuid4(),
        "ams-1",
        "xray_client",
        uuid4(),
        2,
        None,
        "repair_failed",
        datetime(2026, 1, 1, tzinfo=UTC),
        "agent_unreachable",
    )
    service.history = ReconciliationHistoryPage([entry], 26)
    with make_client(topology_service=service) as client:
        _authenticated(client)
        response = client.get(
            "/v1/admin/reconciliation-history",
            params={
                "server_id": str(entry.server_id),
                "target_id": str(entry.target_id),
                "outcome": "repair_failed",
                "limit": 25,
                "offset": 1,
            },
        )
    assert response.status_code == 200
    assert service.history_query == {
        "server_id": entry.server_id,
        "target_id": entry.target_id,
        "outcome": "repair_failed",
        "limit": 25,
        "offset": 1,
    }
    assert response.json() == {
        "items": [
            {
                "id": str(entry.id),
                "server_id": str(entry.server_id),
                "server_code": "ams-1",
                "target_kind": "xray_client",
                "target_id": str(entry.target_id),
                "desired_generation": 2,
                "observed_generation": None,
                "outcome": "repair_failed",
                "checked_at": "2026-01-01T00:00:00Z",
                "error_code": "agent_unreachable",
            }
        ],
        "total": 26,
        "limit": 25,
        "offset": 1,
    }
    assert response.headers["cache-control"] == "no-store"


def test_reconciliation_history_empty_and_unavailable() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/reconciliation-history")
        assert response.json() == {"items": [], "total": 0, "limit": 25, "offset": 0}
        cast(FastAPI, client.app).state.topology_admin_service = None
        response = client.get("/v1/admin/reconciliation-history")
        assert response.status_code == 503


def test_vpn_server_reconciliation_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/vpn-servers/reconciliation")

    assert response.status_code == 401


def test_vpn_server_reconciliation_returns_only_counts_without_caching() -> None:
    service = FakeTopologyAdminService()
    server_id = uuid4()
    service.reconciliation = [VpnServerReconciliationEntry(server_id, "ams-1", 2, 3, 1)]
    with make_client(topology_service=service) as client:
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers/reconciliation")

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "server_id": str(server_id),
                "code": "ams-1",
                "pending_provisions": 2,
                "pending_revocations": 3,
                "failed_records": 1,
            }
        ]
    }
    assert response.headers["cache-control"] == "no-store"


def test_vpn_server_reconciliation_empty_inventory() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers/reconciliation")

    assert response.json() == {"items": []}


def test_vpn_server_reconciliation_service_unavailable() -> None:
    with make_client() as client:
        cast(FastAPI, client.app).state.topology_admin_service = None
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers/reconciliation")

    assert response.status_code == 503


def test_protocols_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/protocols")

    assert response.status_code == 401


def test_protocols_returns_empty_list_today() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/protocols")

    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_protocol_profiles_returns_mapped_items() -> None:
    service = FakeTopologyAdminService()
    service.profiles = [
        ProtocolProfileEntry(
            id=uuid4(),
            protocol_id=uuid4(),
            code="wireguard-default",
            version=1,
            display_name="WireGuard default",
            state="draft",
            transport=None,
            transport_security=None,
            requires_udp=True,
            is_full_tunnel=True,
        )
    ]
    with make_client(topology_service=service) as client:
        _authenticated(client)
        response = client.get("/v1/admin/protocol-profiles")

    assert response.status_code == 200
    assert response.json()["items"][0]["code"] == "wireguard-default"
    assert response.headers["cache-control"] == "no-store"


def test_vpn_servers_returns_empty_list_today() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers")

    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_vpn_servers_service_unavailable() -> None:
    app = FastAPI()
    settings = Settings(env="test")
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.topology_admin_service = None
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/vpn-servers")

    assert response.status_code == 503


def test_vpn_server_health_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/vpn-servers/health")

    assert response.status_code == 401


def test_vpn_server_health_returns_mapped_items() -> None:
    service = FakeTopologyAdminService()
    service.health = [
        VpnServerHealthEntry(
            server_id=uuid4(),
            code="ams-1",
            state="healthy",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            latency_ms=12,
            agent_version="1.0.0",
            interface_up=True,
            peer_count=3,
        )
    ]
    with make_client(topology_service=service) as client:
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers/health")

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["code"] == "ams-1"
    assert item["state"] == "healthy"
    assert item["latency_ms"] == 12
    assert item["peer_count"] == 3
    assert response.headers["cache-control"] == "no-store"


def test_vpn_server_health_service_unavailable() -> None:
    app = FastAPI()
    settings = Settings(env="test")
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.topology_admin_service = None
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/vpn-servers/health")

    assert response.status_code == 503
