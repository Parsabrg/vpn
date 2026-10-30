"""Changing Hysteria2's clients without restarting Hysteria2.

With the client list in its config, every connect and disconnect rewrote the
file and restarted the service, dropping every Hysteria2 session on the
server. With live client updates on, Hysteria asks the agent about each new
connection instead, and removed clients are kicked. Measured on the real
v2.9.2 before this was built: the HTTP auth request carries `addr`, `auth` and
`tx`; the returned `id` names the session in `/online`, `/traffic` and
`/kick`; and `/kick` closed a live download at once.
"""

import asyncio
import json
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

import pytest
from test_hysteria_config_store import PROFILE

import nebula_agent.drivers.xray as xray
import nebula_agent.main as agent_main
from nebula_agent.drivers._exec import CompletedRun
from nebula_agent.drivers.fake import FakeXrayRunner
from nebula_agent.drivers.hysteria_config_store import (
    HYSTERIA_AUTH_PATH,
    HYSTERIA_AUTH_PORT,
    TRAFFIC_STATS_PORT,
    render_hysteria_server_config,
    traffic_stats_secret,
)
from nebula_agent.drivers.xray import NativeXrayDriver
from nebula_agent.drivers.xray_base import (
    ProvisionXrayClientRequest,
    ReconcileXrayClientRequest,
    RevokeXrayClientRequest,
)
from nebula_agent.drivers.xray_config_store import (
    DesiredXrayState,
    RenderedXrayClient,
    XrayConfigStore,
    client_email,
)
from nebula_agent.hysteria_auth import HysteriaAuthServer
from nebula_agent.settings import Settings

HYSTERIA = "hysteria2"
API_HOST = "127.25.41.4"


def _settings(tmp_path: Path, *, live: bool = True) -> Settings:
    settings = Settings(
        env="test",
        xray_enabled=True,
        xray_driver="native",
        xray_hysteria_enabled=True,
        xray_hysteria_obfs_password="obfs-for-testing",  # noqa: S106 - test fixture
        xray_tls_cert_file=PurePosixPath("/etc/nebula/tls/cert.pem"),
        xray_tls_key_file=PurePosixPath("/etc/nebula/tls/key.pem"),
        xray_live_client_updates=live,
        xray_api_host=API_HOST,
    )
    return settings.model_copy(
        update={"xray_hysteria_config_file": PurePosixPath(str(tmp_path / "hysteria.yaml"))}
    )


def _driver(tmp_path: Path, *, live: bool = True) -> NativeXrayDriver:
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    return NativeXrayDriver(_settings(tmp_path, live=live), store, profiles=())


class Host:
    """systemctl and xray as far as the driver can tell, counting restarts."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    async def __call__(
        self, argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        self.calls.append(list(argv))
        if argv[1] == "is-active":
            return CompletedRun(0, b"active\n", b"")
        return CompletedRun(0, b"{}", b"")

    def restarts(self, unit: str) -> int:
        return sum(1 for call in self.calls if call[1:3] == ["restart", unit])


class Kicks:
    def __init__(self, error: Exception | None = None) -> None:
        self.sent: list[tuple[str, str, list[str]]] = []
        self.error = error

    def __call__(self, url: str, secret: str, labels: list[str]) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append((url, secret, labels))


def _provision(client_uuid: UUID, profile: str = HYSTERIA) -> ProvisionXrayClientRequest:
    return ProvisionXrayClientRequest(
        idempotency_key=uuid4(),
        correlation_id=uuid4(),
        target_kind="xray_client",
        target_id=uuid4(),
        desired_generation=1,
        client_uuid=client_uuid,
        protocol_profile_code=profile,
    )


def _revoke(client_uuid: UUID) -> RevokeXrayClientRequest:
    return RevokeXrayClientRequest(
        idempotency_key=uuid4(),
        correlation_id=uuid4(),
        target_kind="xray_client",
        target_id=uuid4(),
        client_uuid=client_uuid,
        protocol_profile_code=HYSTERIA,
        desired_generation=2,
    )


def _setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, live: bool = True
) -> tuple[NativeXrayDriver, Host, Kicks]:
    driver = _driver(tmp_path, live=live)
    host = Host()
    kicks = Kicks()
    monkeypatch.setattr(xray, "run_fixed_argv", host)
    monkeypatch.setattr(xray, "_post_hysteria_kick", kicks)
    return driver, host, kicks


class TestRendering:
    def test_http_auth_lists_nobody(self) -> None:
        client = UUID("11111111-1111-1111-1111-111111111111")
        text = render_hysteria_server_config(
            (client,), PROFILE, auth_url="http://127.25.41.4:25415/hysteria/auth"
        )

        assert "  type: http\n" in text
        assert '    url: "http://127.25.41.4:25415/hysteria/auth"' in text
        assert "userpass" not in text
        assert str(client) not in text

    def test_http_auth_renders_the_same_file_whoever_is_provisioned(self) -> None:
        # The whole point: nothing to restart for.
        url = "http://127.25.41.4:25415/hysteria/auth"
        empty = render_hysteria_server_config((), PROFILE, auth_url=url)
        full = render_hysteria_server_config((uuid4(), uuid4()), PROFILE, auth_url=url)
        assert empty == full

    def test_traffic_stats_listen_on_the_api_address(self) -> None:
        text = render_hysteria_server_config((), PROFILE, api_host=API_HOST)
        assert f"  listen: {API_HOST}:{TRAFFIC_STATS_PORT}\n" in text


class TestAuthorize:
    def _driver_with(self, tmp_path: Path, *clients: tuple[UUID, str]) -> NativeXrayDriver:
        driver = _driver(tmp_path)
        store = driver._config_store
        desired = DesiredXrayState(
            clients=tuple(
                RenderedXrayClient(client_uuid=u, protocol_profile_code=p) for u, p in clients
            )
        )
        store.promote_candidate_to_last_known_good(
            store.write_candidate_atomically(store.render_candidate(desired))
        )
        return driver

    def test_a_recorded_client_is_admitted_as_its_label(self, tmp_path: Path) -> None:
        client = uuid4()
        driver = self._driver_with(tmp_path, (client, HYSTERIA))

        assert driver.authorize_hysteria(str(client)) == client_email(client)
        assert driver.authorize_hysteria(f"{client}:{client}") == client_email(client)
        assert driver.authorize_hysteria(str(client).upper()) == client_email(client)

    def test_the_label_is_never_the_credential(self, tmp_path: Path) -> None:
        client = uuid4()
        driver = self._driver_with(tmp_path, (client, HYSTERIA))

        label = driver.authorize_hysteria(str(client))
        assert label is not None
        assert str(client) not in label

    def test_anything_else_is_refused(self, tmp_path: Path) -> None:
        client = uuid4()
        vless_client = uuid4()
        driver = self._driver_with(tmp_path, (client, HYSTERIA), (vless_client, "vless-xhttp-tls"))

        assert driver.authorize_hysteria(str(uuid4())) is None
        # Recorded, but for another transport.
        assert driver.authorize_hysteria(str(vless_client)) is None
        assert driver.authorize_hysteria(f"{client}:{uuid4()}") is None
        assert driver.authorize_hysteria("{" + str(client) + "}") is None
        assert driver.authorize_hysteria(client.hex) is None
        assert driver.authorize_hysteria("") is None
        assert driver.authorize_hysteria("not a uuid") is None

    def test_nobody_is_admitted_where_hysteria_is_not_served(self, tmp_path: Path) -> None:
        store = XrayConfigStore(
            PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
        )
        driver = NativeXrayDriver(Settings(env="test"), store, profiles=())
        assert driver.authorize_hysteria(str(uuid4())) is None


class TestApplying:
    def test_a_second_client_does_not_restart_hysteria(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        driver, host, _ = _setup(tmp_path, monkeypatch)

        async def scenario() -> None:
            await driver.provision_client(_provision(uuid4()))
            await driver.provision_client(_provision(uuid4()))
            await driver.provision_client(_provision(uuid4()))

        asyncio.run(scenario())

        # Once, to put the HTTP-auth config in place; never for a client.
        assert host.restarts("nebula-hysteria") == 1

    def test_without_live_updates_each_client_restarts_hysteria(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        driver, host, kicks = _setup(tmp_path, monkeypatch, live=False)

        async def scenario() -> None:
            client = uuid4()
            await driver.provision_client(_provision(client))
            await driver.provision_client(_provision(uuid4()))
            await driver.revoke_client(_revoke(client))

        asyncio.run(scenario())

        assert host.restarts("nebula-hysteria") == 3
        # The restart already closed everyone's sessions.
        assert kicks.sent == []

    def test_a_removed_client_is_kicked_by_label(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        driver, host, kicks = _setup(tmp_path, monkeypatch)
        leaving = uuid4()

        async def scenario() -> None:
            await driver.provision_client(_provision(uuid4()))
            await driver.provision_client(_provision(leaving))
            response = await driver.revoke_client(_revoke(leaving))
            assert response.state == "revoked"

        asyncio.run(scenario())

        assert host.restarts("nebula-hysteria") == 1
        assert kicks.sent == [
            (
                f"http://{API_HOST}:{TRAFFIC_STATS_PORT}/kick",
                traffic_stats_secret(driver._hysteria_profile),  # type: ignore[arg-type]
                [client_email(leaving)],
            )
        ]
        # And it is refused if it comes straight back.
        assert driver.authorize_hysteria(str(leaving)) is None

    def test_removing_a_client_of_another_transport_kicks_nobody(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        driver, _, kicks = _setup(tmp_path, monkeypatch)

        async def scenario() -> None:
            await driver.provision_client(_provision(uuid4()))
            await driver.provision_client(_provision(uuid4()))

        asyncio.run(scenario())

        assert kicks.sent == []

    def test_a_failed_kick_still_revokes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        driver, _, _ = _setup(tmp_path, monkeypatch)
        monkeypatch.setattr(xray, "_post_hysteria_kick", Kicks(OSError("connection refused")))
        leaving = uuid4()

        async def scenario() -> None:
            await driver.provision_client(_provision(leaving))
            response = await driver.revoke_client(_revoke(leaving))
            assert response.state == "revoked"

        asyncio.run(scenario())

        assert driver.authorize_hysteria(str(leaving)) is None


class TestReconciling:
    def test_a_recorded_client_is_served_under_http_auth(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # There is no list in the file to find it in. Reporting it missing
        # would have reconciliation re-provision every Hysteria2 client on
        # every sweep.
        driver, _, _ = _setup(tmp_path, monkeypatch)
        client = uuid4()

        async def scenario() -> str:
            await driver.provision_client(_provision(client))
            response = await driver.reconcile_client(
                ReconcileXrayClientRequest(
                    correlation_id=uuid4(),
                    target_kind="xray_client",
                    target_id=uuid4(),
                    client_uuid=client,
                    protocol_profile_code=HYSTERIA,
                    desired_generation=1,
                )
            )
            return response.outcome

        assert asyncio.run(scenario()) == "in_sync"
        assert driver._live_hysteria_uuids() == {str(client)}


async def _post(port: int, raw: bytes) -> tuple[int, dict[str, object]]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    response = await reader.read()
    writer.close()
    head, _, body = response.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    assert b"Connection: close" in head
    return status, json.loads(body)


def _request(body: bytes, *, path: str = "/hysteria/auth", extra: str = "") -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n{extra}\r\n"
    ).encode() + body


class TestAuthServer:
    def _run(self, *requests: bytes) -> list[tuple[int, dict[str, object]]]:
        admitted = {"good": "label-for-good"}

        async def scenario() -> list[tuple[int, dict[str, object]]]:
            server = HysteriaAuthServer("127.0.0.1", 0, "/hysteria/auth", admitted.get)
            await server.start()
            try:
                return [await _post(server.port, raw) for raw in requests]
            finally:
                await server.close()

        return asyncio.run(scenario())

    def test_what_hysteria_sends_is_answered(self) -> None:
        body = json.dumps({"addr": "5.6.7.8:1234", "auth": "good", "tx": 0}).encode()
        refused = json.dumps({"addr": "5.6.7.8:1234", "auth": "bad", "tx": 0}).encode()

        answers = self._run(_request(body), _request(refused))

        assert answers == [
            (200, {"ok": True, "id": "label-for-good"}),
            (200, {"ok": False, "id": ""}),
        ]

    def test_anything_that_is_not_that_request_is_refused(self) -> None:
        good = json.dumps({"auth": "good"}).encode()
        answers = self._run(
            _request(good, path="/elsewhere"),
            b"GET /hysteria/auth HTTP/1.1\r\nHost: x\r\n\r\n",
            _request(b"{not json"),
            _request(json.dumps({"auth": 7}).encode()),
            _request(json.dumps(["auth"]).encode()),
            b"POST /hysteria/auth HTTP/1.1\r\nHost: x\r\n\r\n",
            _request(good, extra="Transfer-Encoding: chunked\r\n"),
            b"POST /hysteria/auth HTTP/1.1\r\nContent-Length: 999999\r\n\r\n",
            b"POST /hysteria/auth HTTP/1.1\r\nContent-Length: nope\r\n\r\n",
        )

        assert [status for status, _ in answers] == [404, 404, 400, 400, 400, 400, 400, 400, 400]
        assert all(payload == {"ok": False, "id": ""} for _, payload in answers)

    def test_a_request_that_never_finishes_is_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import nebula_agent.hysteria_auth as hysteria_auth

        monkeypatch.setattr(hysteria_auth, "_READ_TIMEOUT_SECONDS", 0.2)
        answers = self._run(b"POST /hysteria/auth HTTP/1.1\r\nContent-Length: 10\r\n\r\n{")
        assert answers == [(400, {"ok": False, "id": ""})]

    def test_the_bound_port_is_reported(self) -> None:
        async def scenario() -> tuple[int, int]:
            server = HysteriaAuthServer("127.0.0.1", 0, "/x", lambda _auth: None)
            before = server.port
            await server.start()
            try:
                return before, server.port
            finally:
                await server.close()

        before, bound = asyncio.run(scenario())
        assert before == 0
        assert bound > 0


class TestStartup:
    def test_nothing_listens_without_live_updates(self, tmp_path: Path) -> None:
        server = asyncio.run(
            agent_main._start_hysteria_auth(_settings(tmp_path, live=False), FakeXrayRunner())
        )
        assert server is None

    def test_the_listener_starts_on_the_api_address(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(agent_main, "HYSTERIA_AUTH_PORT", 0)
        settings = _settings(tmp_path).model_copy(update={"xray_api_host": "127.0.0.1"})

        async def scenario() -> bool:
            server = await agent_main._start_hysteria_auth(settings, FakeXrayRunner())
            assert server is not None
            try:
                return server.port > 0
            finally:
                await server.close()

        assert asyncio.run(scenario())

    def test_a_listener_that_cannot_start_does_not_stop_the_agent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def refuse(_self: HysteriaAuthServer) -> None:
            raise OSError("address in use")

        monkeypatch.setattr(HysteriaAuthServer, "start", refuse)
        server = asyncio.run(agent_main._start_hysteria_auth(_settings(tmp_path), FakeXrayRunner()))
        assert server is None


def test_the_auth_url_is_the_listener() -> None:
    assert HYSTERIA_AUTH_PATH.startswith("/")
    assert HYSTERIA_AUTH_PORT not in (TRAFFIC_STATS_PORT, 25414)
