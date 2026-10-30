"""The security dashboard says only what it can observe."""

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_api import security_status
from nebula_api.security_status import (
    Check,
    SecurityStatusService,
    age_status,
    expiry_status,
)
from nebula_api.settings import Settings
from nebula_api.topology_admin.service import TopologyAdminService

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


def _certificate(days_left: int) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=days_left, hours=1))
        .sign(key, hashes.SHA256())
    )


class FakeRedis:
    def __init__(self, answers: bool = True) -> None:
        self.answers = answers

    async def ping(self) -> bool:
        if not self.answers:
            raise ConnectionError("down")
        return True


class FakeTopology:
    def __init__(self, failed: int = 0, pending: int = 0) -> None:
        self.rows = [
            SimpleNamespace(
                pending_provisions=pending, pending_revocations=0, failed_records=failed
            )
        ]

    async def get_vpn_server_reconciliation(self) -> list[Any]:
        return self.rows


class Scripted(SecurityStatusService):
    """Answers queries from a table instead of a database."""

    def __init__(self, tmp: Path, answers: dict[str, Any], **kwargs: Any) -> None:
        agent = tmp / "agent.pem"
        agent.write_bytes(_certificate(200).public_bytes(Encoding.PEM))
        settings = Settings(
            env="test",
            agent_client_cert_file=agent,
            node_ca_certificate_file=tmp / "missing.pem",
        )
        super().__init__(
            cast(AsyncEngine, None),
            kwargs.pop("redis", FakeRedis()),
            settings,
            cast(TopologyAdminService, kwargs.pop("topology", FakeTopology())),
            clock=lambda: NOW,
            public_certificate=kwargs.pop("public", lambda _url: _certificate(60)),
        )
        self.answers = answers

    def _answer(self, sql: str) -> Any:
        for fragment, value in self.answers.items():
            if fragment in sql:
                if isinstance(value, Exception):
                    raise value
                return value
        raise AssertionError(f"unexpected query: {sql}")

    async def _scalar(self, sql: str) -> Any:
        return self._answer(sql)

    async def _row(self, sql: str) -> Any:
        return self._answer(sql)


def _checks(service: SecurityStatusService, monkeypatch: Any) -> dict[str, Check]:
    async def current(_engine: object) -> bool:
        return True

    monkeypatch.setattr(security_status, "schema_is_current", current)
    return {check.key: check for check in asyncio.run(service.checks())}


HEALTHY = {
    "select 1": 1,
    "email_deliveries": (0, None),
    "credential_usage": NOW - timedelta(seconds=10),
    "backup_completed": NOW - timedelta(hours=5),
}


def test_a_healthy_deployment_reads_ok(tmp_path: Path, monkeypatch: Any) -> None:
    checks = _checks(Scripted(tmp_path, HEALTHY), monkeypatch)

    for key in ("database", "schema", "redis", "worker", "usage", "backup", "tls", "keys"):
        assert checks[key].status == "ok", checks[key]
    assert checks["agent_certificate"].status == "ok"
    assert checks["reconciliation"].detail == "Clean"


def test_what_cannot_be_read_is_unknown_not_ok(tmp_path: Path, monkeypatch: Any) -> None:
    answers = {**HEALTHY, "backup_completed": None, "credential_usage": None}

    def unreachable(_url: str) -> x509.Certificate:
        raise OSError("no route")

    checks = _checks(Scripted(tmp_path, answers, public=unreachable), monkeypatch)

    assert checks["backup"].status == "unknown"
    assert checks["usage"].status == "unknown"
    assert checks["tls"].status == "unknown"
    assert checks["node_ca"].status == "unknown"  # the file does not exist


def test_failures_are_said(tmp_path: Path, monkeypatch: Any) -> None:
    answers = {
        **HEALTHY,
        "select 1": RuntimeError("down"),
        "email_deliveries": (4, NOW - timedelta(hours=1)),
        "backup_completed": NOW - timedelta(days=3),
    }
    checks = _checks(
        Scripted(
            tmp_path,
            answers,
            redis=FakeRedis(answers=False),
            topology=FakeTopology(failed=2, pending=1),
            public=lambda _url: _certificate(5),
        ),
        monkeypatch,
    )

    assert checks["database"].status == "failing"
    assert checks["redis"].status == "failing"
    assert checks["worker"].status == "warning"
    assert checks["worker"].detail.startswith("4 waiting")
    assert checks["backup"].status == "failing"
    assert checks["reconciliation"].status == "warning"
    assert checks["tls"].status == "failing"


def test_thresholds() -> None:
    assert age_status(timedelta(hours=29), warning=timedelta(hours=30)) == "ok"
    assert age_status(timedelta(hours=31), warning=timedelta(hours=30)) == "warning"
    assert (
        age_status(timedelta(hours=50), warning=timedelta(hours=30), failing=timedelta(hours=48))
        == "failing"
    )
    assert expiry_status(60) == "ok"
    assert expiry_status(20) == "warning"
    assert expiry_status(7) == "failing"


class _Admin:
    async def principal(self, _token: str) -> Any:
        from uuid import uuid4

        from nebula_api.auth.admin_service import AdminPrincipal
        from nebula_api.models.types import AdminRole

        return AdminPrincipal(uuid4(), uuid4(), AdminRole.AUDITOR, False, "totp")


class _Status:
    async def checks(self) -> list[Check]:
        return [Check("backup", "Last backup", "ok", "Uploaded 5 h ago", NOW)]


def _get(service: object | None) -> Any:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from nebula_api.auth.http import install_auth_http_safeguards
    from nebula_api.topology_admin.routes import router

    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = _Admin()
    app.state.security_status_service = service
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        return client.get("/v1/admin/security-status")


def test_the_route_returns_the_checks_uncached() -> None:
    response = _get(_Status())

    assert response.status_code == 200
    assert response.json()["checks"][0]["status"] == "ok"
    assert response.headers["cache-control"] == "no-store"


def test_the_route_is_unavailable_without_its_service() -> None:
    assert _get(None).status_code == 503
