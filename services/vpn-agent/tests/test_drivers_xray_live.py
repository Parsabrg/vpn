"""Changing Xray's clients without restarting it.

A restart drops every connection on the server, and connects and disconnects
used to cause one each. These tests drive the driver against a stand-in for
the xray binary, its API and systemctl, built on what the real ones were
measured to do: `adu` exits 0 even when Xray refuses the user, removing a user
leaves its open connections running, and a restart loads whatever the config
file says.
"""

import asyncio
import json
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

import pytest
from test_drivers_xray import _provision_request

import nebula_agent.drivers.xray as xray
from nebula_agent.drivers._exec import CompletedRun
from nebula_agent.drivers.errors import ApplyError
from nebula_agent.drivers.xray import NativeXrayDriver
from nebula_agent.drivers.xray_base import RevokeXrayClientRequest
from nebula_agent.drivers.xray_config_store import STATS_API_PORT, XrayConfigStore, client_email
from nebula_agent.settings import Settings

_OK = CompletedRun(0, b"", b"")


class FakeXray:
    """Xray, its API and systemctl, as far as the driver can tell."""

    def __init__(self, driver: NativeXrayDriver) -> None:
        self._driver = driver
        # Per inbound tag: the clients the running process serves, by email.
        self.live: dict[str, dict[str, str]] = {}
        self.calls: list[list[str]] = []
        self.stdin: list[bytes] = []
        self.restarts = 0
        self.traffic: dict[str, int] = {}
        # Added to a client's traffic on every statsquery: a connection
        # that is still carrying bytes.
        self.traffic_growth: dict[str, int] = {}
        self.refuse_adds = False
        self.api_down = False

    def _load_served(self) -> None:
        config = json.loads(self._driver._config_store.xray_config_path.read_text())
        self.live = {
            inbound["tag"]: {
                c["email"]: c.get("id", c.get("password")) for c in inbound["settings"]["clients"]
            }
            for inbound in config["inbounds"]
            if inbound.get("protocol") in ("vless", "shadowsocks")
        }

    async def __call__(
        self, argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        self.calls.append(list(argv))
        # Yield, as a real subprocess would, so concurrent operations get a
        # chance to interleave.
        await asyncio.sleep(0)
        if argv[1] == "run":
            return _OK
        if argv[1] == "restart":
            self.restarts += 1
            self._load_served()
            return _OK
        if argv[1] == "is-active":
            return CompletedRun(0, b"active\n", b"")
        assert argv[1] == "api", argv
        if self.api_down:
            return CompletedRun(1, b"", b"failed to dial")
        command, arguments = argv[2], argv[4:]
        if command == "inbounduser":
            tag = arguments[0].removeprefix("-tag=")
            users = [
                {"email": email, "account": {"id": client_id}}
                for email, client_id in self.live.get(tag, {}).items()
            ]
            return CompletedRun(0, json.dumps({"users": users} if users else {}).encode(), b"")
        if command == "rmu":
            tag = arguments[0].removeprefix("-tag=")
            for email in arguments[1:]:
                self.live.get(tag, {}).pop(email, None)
            return _OK
        if command == "adu":
            assert arguments == ["stdin:"]
            assert stdin is not None
            self.stdin.append(stdin)
            if not self.refuse_adds:
                for inbound in json.loads(stdin)["inbounds"]:
                    for client in inbound["settings"]["clients"]:
                        self.live.setdefault(inbound["tag"], {})[client["email"]] = client.get(
                            "id", client.get("password")
                        )
            # Exactly what Xray does with a user it refused.
            return _OK
        if command == "statsquery":
            for email, growth in self.traffic_growth.items():
                self.traffic[email] = self.traffic.get(email, 0) + growth
            rows = [
                {"name": f"user>>>{email}>>>traffic>>>downlink", "value": value}
                for email, value in self.traffic.items()
            ]
            return CompletedRun(0, json.dumps({"stat": rows}).encode(), b"")
        raise AssertionError(f"unexpected xray api command {command!r}")

    def served_emails(self, tag: str = "vless-xhttp-tls") -> set[str]:
        return set(self.live.get(tag, {}))


def _driver(tmp_path: Path, *, live: bool = True) -> NativeXrayDriver:
    settings = Settings(env="test", xray_live_client_updates=live, xray_api_host="127.25.41.4")
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    return NativeXrayDriver(settings, store)


def _revoke(client_uuid: UUID) -> RevokeXrayClientRequest:
    return RevokeXrayClientRequest(
        idempotency_key=uuid4(),
        correlation_id=uuid4(),
        target_kind="xray_client",
        target_id=uuid4(),
        client_uuid=client_uuid,
        protocol_profile_code="vless-xhttp-tls",
        desired_generation=2,
    )


def _setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, live: bool = True
) -> tuple[NativeXrayDriver, FakeXray]:
    driver = _driver(tmp_path, live=live)
    fake = FakeXray(driver)
    monkeypatch.setattr(xray, "run_fixed_argv", fake)
    monkeypatch.setattr(xray, "_LINGER_POLL_SECONDS", 0.0)
    return driver, fake


def test_without_live_updates_every_change_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch, live=False)

    async def scenario() -> None:
        await driver.provision_client(_provision_request())
        await driver.provision_client(_provision_request())

    asyncio.run(scenario())

    assert fake.restarts == 2
    assert not any(call[1] == "api" for call in fake.calls)


def test_the_first_client_starts_xray_the_only_way_it_can(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing is being served yet, so there is no running process to change.
    driver, fake = _setup(tmp_path, monkeypatch)

    response = asyncio.run(driver.provision_client(_provision_request()))

    assert response.state == "active"
    assert fake.restarts == 1


def test_a_connect_adds_its_client_without_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch)
    first = _provision_request()
    second = _provision_request()

    async def scenario() -> None:
        await driver.provision_client(first)
        await driver.provision_client(second)

    asyncio.run(scenario())

    # One restart, for the first client. The second connect dropped nobody.
    assert fake.restarts == 1
    assert fake.served_emails() == {
        client_email(first.client_uuid),
        client_email(second.client_uuid),
    }
    # And what is on disk agrees, so a later restart serves the same set.
    served = json.loads(driver._config_store.xray_config_path.read_text())
    xhttp = next(i for i in served["inbounds"] if i["tag"] == "vless-xhttp-tls")
    assert {c["email"] for c in xhttp["settings"]["clients"]} == fake.served_emails()


def test_a_disconnect_removes_its_client_without_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch)
    staying = _provision_request()
    leaving = _provision_request()

    async def scenario() -> None:
        await driver.provision_client(staying)
        await driver.provision_client(leaving)
        response = await driver.revoke_client(_revoke(leaving.client_uuid))
        assert response.state == "revoked"

    asyncio.run(scenario())

    assert fake.restarts == 1
    assert fake.served_emails() == {client_email(staying.client_uuid)}


def test_no_credential_is_ever_put_on_a_command_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every local user can read another process's argv. A client's UUID is
    # its credential, so it goes over stdin, and removal names the digest.
    driver, fake = _setup(tmp_path, monkeypatch)
    first = _provision_request()
    second = _provision_request()

    async def scenario() -> None:
        await driver.provision_client(first)
        await driver.provision_client(second)
        await driver.revoke_client(_revoke(second.client_uuid))

    asyncio.run(scenario())

    commands = [" ".join(call) for call in fake.calls]
    for secret in (str(first.client_uuid), str(second.client_uuid)):
        assert not any(secret in command for command in commands)
    assert any(str(second.client_uuid) in payload.decode() for payload in fake.stdin)
    assert any(f"--server=127.25.41.4:{STATS_API_PORT}" in call for call in fake.calls)


def test_a_client_xray_refused_is_applied_by_restarting_instead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `adu` reports success for a user it did not add. Believing it would
    # tell the caller a client is live that Xray rejects.
    driver, fake = _setup(tmp_path, monkeypatch)
    first = _provision_request()
    second = _provision_request()

    async def scenario() -> None:
        await driver.provision_client(first)
        fake.refuse_adds = True
        response = await driver.provision_client(second)
        assert response.state == "active"

    asyncio.run(scenario())

    assert fake.restarts == 2
    assert client_email(second.client_uuid) in fake.served_emails()


def test_an_api_that_does_not_answer_is_applied_by_restarting_instead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch)
    second = _provision_request()

    async def scenario() -> None:
        await driver.provision_client(_provision_request())
        fake.api_down = True
        response = await driver.provision_client(second)
        assert response.state == "active"

    asyncio.run(scenario())

    assert fake.restarts == 2
    assert client_email(second.client_uuid) in fake.served_emails()


def test_a_change_to_more_than_the_clients_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The API changes users. Anything else in the file -- here, what an
    # older build rendered -- only takes effect on a restart.
    driver, fake = _setup(tmp_path, monkeypatch)

    async def scenario() -> None:
        await driver.provision_client(_provision_request())
        path = driver._config_store.xray_config_path
        served = json.loads(path.read_text())
        served["api"]["services"] = ["StatsService"]
        path.write_text(json.dumps(served))
        await driver.provision_client(_provision_request())

    asyncio.run(scenario())

    assert fake.restarts == 2


def test_an_unreadable_served_config_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch)

    async def scenario() -> None:
        await driver.provision_client(_provision_request())
        driver._config_store.xray_config_path.write_text("not json")
        await driver.provision_client(_provision_request())

    asyncio.run(scenario())

    assert fake.restarts == 2


def test_two_connects_at_once_both_end_up_served(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each change reads the recorded set, adds to it and writes it back. At
    # the same time, without the lock, each would write a set missing the
    # other's client.
    driver, fake = _setup(tmp_path, monkeypatch)
    requests = [_provision_request() for _ in range(3)]

    async def scenario() -> None:
        await driver.provision_client(_provision_request())
        await asyncio.gather(*(driver.provision_client(r) for r in requests))

    asyncio.run(scenario())

    recorded = {c.client_uuid for c in driver._config_store.read_last_known_good().clients}
    assert {r.client_uuid for r in requests} <= recorded
    assert {client_email(r.client_uuid) for r in requests} <= fake.served_emails()


class TestConnectionsThatOutliveTheirClient:
    def test_traffic_after_removal_restarts_xray(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Removal leaves an open connection running. A revoke that has to
        # stop someone -- a spent allowance -- would otherwise not.
        driver, fake = _setup(tmp_path, monkeypatch)
        leaving = _provision_request()
        email = client_email(leaving.client_uuid)

        async def scenario() -> None:
            await driver.provision_client(_provision_request())
            await driver.provision_client(leaving)
            fake.traffic[email] = 1_000
            fake.traffic_growth[email] = 500
            await driver.revoke_client(_revoke(leaving.client_uuid))
            assert driver._linger_task is not None
            await asyncio.wait_for(driver._linger_task, timeout=5)

        asyncio.run(scenario())

        assert fake.restarts == 2
        assert driver._lingering == {}

    def test_a_quiet_removed_client_restarts_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The ordinary disconnect: its connections closed before the revoke.
        driver, fake = _setup(tmp_path, monkeypatch)
        monkeypatch.setattr(xray, "_LINGER_WATCH_SECONDS", 0.0)
        leaving = _provision_request()

        async def scenario() -> None:
            await driver.provision_client(_provision_request())
            await driver.provision_client(leaving)
            fake.traffic[client_email(leaving.client_uuid)] = 1_000
            await driver.revoke_client(_revoke(leaving.client_uuid))
            assert driver._linger_task is not None
            await asyncio.wait_for(driver._linger_task, timeout=5)

        asyncio.run(scenario())

        assert fake.restarts == 1
        assert driver._lingering == {}

    def test_a_client_served_again_is_not_cut_off(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Disconnect and reconnect in quick succession: the traffic is the
        # new connection's, and restarting for it would drop everyone.
        driver, fake = _setup(tmp_path, monkeypatch)
        monkeypatch.setattr(xray, "_LINGER_WATCH_SECONDS", 0.0)
        client = _provision_request()
        email = client_email(client.client_uuid)

        async def scenario() -> None:
            await driver.provision_client(_provision_request())
            await driver.provision_client(client)
            await driver.revoke_client(_revoke(client.client_uuid))
            await driver.provision_client(client)
            fake.traffic[email] = 1_000
            fake.traffic_growth[email] = 500
            if driver._linger_task is not None:
                await asyncio.wait_for(driver._linger_task, timeout=5)

        asyncio.run(scenario())

        assert fake.restarts == 1
        assert email in fake.served_emails()

    def test_counters_that_cannot_be_read_are_tried_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        driver, fake = _setup(tmp_path, monkeypatch)
        leaving = _provision_request()
        email = client_email(leaving.client_uuid)
        reads = {"count": 0}
        answer = fake.__call__

        async def flaky(
            argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
        ) -> CompletedRun:
            if argv[1:3] == ["api", "statsquery"]:
                reads["count"] += 1
                if reads["count"] == 1:
                    return CompletedRun(1, b"", b"failed to dial")
            return await answer(argv, timeout_seconds=timeout_seconds, stdin=stdin)

        async def scenario() -> None:
            await driver.provision_client(_provision_request())
            await driver.provision_client(leaving)
            monkeypatch.setattr(xray, "run_fixed_argv", flaky)
            fake.traffic[email] = 1_000
            fake.traffic_growth[email] = 500
            await driver.revoke_client(_revoke(leaving.client_uuid))
            assert driver._linger_task is not None
            await asyncio.wait_for(driver._linger_task, timeout=5)

        asyncio.run(scenario())

        assert reads["count"] >= 3
        assert fake.restarts == 2


def test_settings_accept_only_an_ipv4_loopback_api_host() -> None:
    assert Settings(env="test", xray_api_host="127.25.41.4").xray_api_host == "127.25.41.4"
    for unsafe in ("0.0.0.0", "10.0.0.1", "::1", "localhost"):  # noqa: S104 - rejected values
        with pytest.raises(ValueError, match="loopback"):
            Settings(env="test", xray_api_host=unsafe)


def test_unreadable_user_listing_is_applied_by_restarting_instead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver, fake = _setup(tmp_path, monkeypatch)
    answer = fake.__call__

    async def garbled(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        if argv[1:3] == ["api", "inbounduser"]:
            return CompletedRun(0, b"not json", b"")
        return await answer(argv, timeout_seconds=timeout_seconds, stdin=stdin)

    second = _provision_request()

    async def scenario() -> None:
        await driver.provision_client(_provision_request())
        monkeypatch.setattr(xray, "run_fixed_argv", garbled)
        response = await driver.provision_client(second)
        assert response.state == "active"

    asyncio.run(scenario())

    assert fake.restarts == 2
    assert client_email(second.client_uuid) in fake.served_emails()


def test_only_user_traffic_counters_are_totalled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    output = json.dumps(
        {
            "stat": [
                {"name": "user>>>abc>>>traffic>>>uplink", "value": 5},
                {"name": "user>>>abc>>>traffic>>>downlink", "value": "7"},
                {"name": "inbound>>>vless-xhttp-tls>>>traffic>>>uplink", "value": 999},
                {"name": "user>>>abc>>>online"},
                "not a row",
            ]
        }
    ).encode()

    async def stats(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        return CompletedRun(0, output, b"")

    monkeypatch.setattr(xray, "run_fixed_argv", stats)

    assert asyncio.run(driver._user_traffic_totals()) == {"abc": 12}


def test_unreadable_counters_are_an_apply_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)

    async def garbled(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        return CompletedRun(0, b"{not json", b"")

    monkeypatch.setattr(xray, "run_fixed_argv", garbled)

    with pytest.raises(ApplyError, match="unparseable"):
        asyncio.run(driver._user_traffic_totals())


def test_a_failed_restart_for_a_lingering_client_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # It runs in the background, where an exception would go unobserved and
    # the watch would simply stop.
    driver, fake = _setup(tmp_path, monkeypatch)
    leaving = _provision_request()
    email = client_email(leaving.client_uuid)
    answer = fake.__call__

    async def restart_fails(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        if argv[1] == "restart":
            return CompletedRun(1, b"", b"unit failed")
        return await answer(argv, timeout_seconds=timeout_seconds, stdin=stdin)

    async def scenario() -> None:
        await driver.provision_client(_provision_request())
        await driver.provision_client(leaving)
        monkeypatch.setattr(xray, "run_fixed_argv", restart_fails)
        fake.traffic[email] = 1_000
        fake.traffic_growth[email] = 500
        await driver.revoke_client(_revoke(leaving.client_uuid))
        assert driver._linger_task is not None
        await asyncio.wait_for(driver._linger_task, timeout=5)

    asyncio.run(scenario())

    assert driver._lingering == {}


def test_a_shape_that_is_not_a_config_object_cannot_be_compared() -> None:
    assert xray._shape_without_clients("[]") is None
    assert xray._shape_without_clients("{broken") is None
