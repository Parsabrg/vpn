"""One factual security dashboard: what this API can observe, and when.

Every row is evidence the control plane can read for itself -- a query, a
ping, a certificate file, a TLS handshake. Nothing here is a setting echoed
back or a guess: what cannot be observed is "unknown", never "ok". CI scan
results live on GitHub and are not repeated here, since this process cannot
see them.
"""

import asyncio
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from cryptography import x509
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_api.db.schema import schema_is_current
from nebula_api.settings import Settings
from nebula_api.topology_admin.service import TopologyAdminService

Status = Literal["ok", "warning", "failing", "unknown"]
Clock = Callable[[], datetime]

# Backups run daily with up to 30 minutes of jitter.
BACKUP_WARNING = timedelta(hours=30)
BACKUP_FAILING = timedelta(hours=48)
# The usage collector reads every 15 s.
USAGE_WARNING = timedelta(minutes=2)
# Mail the worker should have sent by now.
MAIL_WARNING = timedelta(minutes=10)
CERTIFICATE_WARNING_DAYS = 21
CERTIFICATE_FAILING_DAYS = 7


@dataclass(frozen=True, slots=True)
class Check:
    key: str
    label: str
    status: Status
    detail: str
    observed_at: datetime | None = None


def age_status(age: timedelta, *, warning: timedelta, failing: timedelta | None = None) -> Status:
    if failing is not None and age > failing:
        return "failing"
    return "warning" if age > warning else "ok"


def expiry_status(days_left: int) -> Status:
    if days_left <= CERTIFICATE_FAILING_DAYS:
        return "failing"
    return "warning" if days_left <= CERTIFICATE_WARNING_DAYS else "ok"


def _ago(age: timedelta) -> str:
    seconds = int(age.total_seconds())
    if seconds < 120:
        return f"{seconds} s ago"
    if seconds < 7200:
        return f"{seconds // 60} min ago"
    if seconds < 172800:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


def _fetch_public_certificate(url: str) -> x509.Certificate:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or 443
    pem = ssl.get_server_certificate((host, port), timeout=3)
    return x509.load_pem_x509_certificate(pem.encode())


class SecurityStatusService:
    def __init__(
        self,
        engine: AsyncEngine,
        redis_client: Any,
        settings: Settings,
        topology: TopologyAdminService,
        *,
        clock: Clock = lambda: datetime.now(UTC),
        public_certificate: Callable[[str], x509.Certificate] = _fetch_public_certificate,
    ) -> None:
        self._engine = engine
        self._redis = redis_client
        self._settings = settings
        self._topology = topology
        self._clock = clock
        self._public_certificate = public_certificate

    async def checks(self) -> list[Check]:
        probes: list[Callable[[], Awaitable[Check]]] = [
            self._database,
            self._schema,
            self._redis_check,
            self._mail_queue,
            self._usage_collector,
            self._backup,
            self._reconciliation,
            self._public_tls,
            self._agent_certificate,
            self._node_ca,
        ]
        results = list(await asyncio.gather(*(probe() for probe in probes)))
        results.append(self._keys())
        return results

    async def _scalar(self, sql: str) -> Any:
        async with self._engine.connect() as connection:
            return (await connection.execute(text(sql))).scalar()

    async def _row(self, sql: str) -> Any:
        async with self._engine.connect() as connection:
            return (await connection.execute(text(sql))).one()

    async def _database(self) -> Check:
        started = time.monotonic()
        try:
            await self._scalar("select 1")
        except Exception:
            return Check("database", "PostgreSQL", "failing", "Not answering", self._clock())
        took = round((time.monotonic() - started) * 1000)
        return Check("database", "PostgreSQL", "ok", f"Answering in {took} ms", self._clock())

    async def _schema(self) -> Check:
        try:
            current = await schema_is_current(self._engine)
        except Exception:
            return Check("schema", "Database schema", "unknown", "Could not read the version")
        if current:
            return Check("schema", "Database schema", "ok", "At the version this API expects")
        return Check("schema", "Database schema", "failing", "Not the version this API expects")

    async def _redis_check(self) -> Check:
        try:
            answered = bool(await self._redis.ping())
        except Exception:
            answered = False
        if answered:
            return Check("redis", "Redis", "ok", "Answering", self._clock())
        return Check("redis", "Redis", "failing", "Not answering", self._clock())

    async def _mail_queue(self) -> Check:
        # The worker sends mail; mail left waiting is the visible sign of a
        # worker that is stuck or down.
        try:
            waiting, oldest = await self._row(
                "select count(*), min(available_at) from email_deliveries "
                "where state in ('pending', 'sending')"
            )
        except Exception:
            return Check("worker", "Worker (mail)", "unknown", "Could not read the mail queue")
        if not waiting or oldest is None:
            return Check("worker", "Worker (mail)", "ok", "No mail waiting")
        age = self._clock() - oldest
        return Check(
            "worker",
            "Worker (mail)",
            age_status(age, warning=MAIL_WARNING),
            f"{waiting} waiting, oldest {_ago(age)}",
            oldest,
        )

    async def _usage_collector(self) -> Check:
        try:
            newest = await self._scalar("select max(last_collected_at) from credential_usage")
        except Exception:
            newest = None
        if newest is None:
            return Check("usage", "Usage collector", "unknown", "No counters read yet")
        age = self._clock() - newest
        return Check(
            "usage",
            "Usage collector",
            age_status(age, warning=USAGE_WARNING),
            f"Counters last read {_ago(age)}",
            newest,
        )

    async def _backup(self) -> Check:
        # backup.sh records each completed upload in the audit log.
        try:
            newest = await self._scalar(
                "select max(recorded_at) from audit_logs where reason_code = 'backup_completed'"
            )
        except Exception:
            newest = None
        if newest is None:
            return Check("backup", "Last backup", "unknown", "No completed backup recorded")
        age = self._clock() - newest
        return Check(
            "backup",
            "Last backup",
            age_status(age, warning=BACKUP_WARNING, failing=BACKUP_FAILING),
            f"Uploaded {_ago(age)}",
            newest,
        )

    async def _reconciliation(self) -> Check:
        try:
            rows = await self._topology.get_vpn_server_reconciliation()
        except Exception:
            return Check("reconciliation", "Reconciliation", "unknown", "Could not read it")
        pending = sum(row.pending_provisions + row.pending_revocations for row in rows)
        failed = sum(row.failed_records for row in rows)
        if failed:
            return Check(
                "reconciliation",
                "Reconciliation",
                "warning",
                f"{failed} failed, {pending} pending",
            )
        detail = f"{pending} pending" if pending else "Clean"
        return Check("reconciliation", "Reconciliation", "ok", detail)

    def _certificate_check(self, key: str, label: str, certificate: x509.Certificate) -> Check:
        expires = certificate.not_valid_after_utc
        days = (expires - self._clock()).days
        return Check(key, label, expiry_status(days), f"Expires in {days} days", expires)

    async def _public_tls(self) -> Check:
        try:
            certificate = await asyncio.to_thread(
                self._public_certificate, self._settings.api_public_url
            )
        except Exception:
            return Check("tls", "API TLS certificate", "unknown", "Could not fetch it")
        return self._certificate_check("tls", "API TLS certificate", certificate)

    def _file_certificate(self, key: str, label: str, path: Path) -> Check:
        try:
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
        except Exception:
            return Check(key, label, "unknown", "Could not read it")
        return self._certificate_check(key, label, certificate)

    async def _agent_certificate(self) -> Check:
        return self._file_certificate(
            "agent_certificate",
            "Agent client certificate",
            self._settings.resolved_agent_client_cert_file,
        )

    async def _node_ca(self) -> Check:
        return self._file_certificate(
            "node_ca",
            "Node certificate authority",
            self._settings.resolved_node_ca_certificate_file,
        )

    def _keys(self) -> Check:
        s = self._settings
        return Check(
            "keys",
            "Key versions in use",
            "ok",
            f"Tokens v{s.token_key_version} · MFA v{s.mfa_key_version} · "
            f"VPN credentials v{s.xray_key_version}",
        )
