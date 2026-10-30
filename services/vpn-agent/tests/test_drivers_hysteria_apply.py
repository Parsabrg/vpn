"""The Hysteria2 apply path, which had no tests and shipped broken twice.

Both faults lived here. A config the server could not parse restarted the unit
25,126 times, because the apply reported success as soon as `systemctl restart`
returned. And checking `is-active` exactly once read the normal "activating"
window as a failure, which marked the client failed and left the next revoke
with nothing live to revoke -- the app could not disconnect, which is what
withdrew v0.1.5.

Both fixes are behavioural and invisible to every other test in this suite, so
they are pinned here.
"""

from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest

import nebula_agent.drivers.xray as xray
from nebula_agent.drivers._exec import CompletedRun
from nebula_agent.drivers.errors import ApplyError
from nebula_agent.drivers.hysteria_config_store import NO_CLIENTS_USER
from nebula_agent.drivers.xray import NativeXrayDriver
from nebula_agent.drivers.xray_base import PruneXrayClientsRequest
from nebula_agent.drivers.xray_config_store import (
    DesiredXrayState,
    RenderedXrayClient,
    XrayConfigStore,
)
from nebula_agent.settings import Settings

pytestmark = pytest.mark.anyio

HYSTERIA_PROFILE = "hysteria2"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _settings(tmp_path: Path) -> Settings:
    """Valid production-shaped settings, with only the config path redirected.

    The TLS paths are never opened here -- they are copied into the rendered
    YAML as strings -- so they stay as the absolute POSIX paths a real
    deployment uses, which is also what the validator demands.

    The config file has to be somewhere writable, and a Windows temp path is
    not POSIX-absolute, so the validator rejects it (correctly: it guards a
    real deployment setting). model_copy sets it afterwards rather than
    weakening that validator, so these tests run identically on both
    platforms and production validation is untouched.
    """

    settings = Settings(
        env="test",
        xray_enabled=True,
        xray_driver="native",
        xray_hysteria_enabled=True,
        xray_hysteria_obfs_password="obfs-for-testing",  # noqa: S106 - test fixture
        xray_tls_cert_file=PurePosixPath("/etc/nebula/tls/cert.pem"),
        xray_tls_key_file=PurePosixPath("/etc/nebula/tls/key.pem"),
    )
    return settings.model_copy(
        update={"xray_hysteria_config_file": PurePosixPath(str(tmp_path / "hysteria.yaml"))}
    )


def _driver(tmp_path: Path) -> NativeXrayDriver:
    settings = _settings(tmp_path)
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    return NativeXrayDriver(settings, store, profiles=())


def _state(*uuids: str) -> DesiredXrayState:
    return DesiredXrayState(
        clients=tuple(
            RenderedXrayClient(client_uuid=uuid4(), protocol_profile_code=HYSTERIA_PROFILE)
            for _ in uuids
        )
    )


def _runner(script: list[CompletedRun], calls: list[str]) -> object:
    async def _run(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> object:
        calls.append(argv[1])
        return script.pop(0) if script else CompletedRun(0, b"active\n", b"")

    return _run


async def test_an_unchanged_client_set_does_not_restart_hysteria(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Restarting drops every live Hysteria2 session. Doing it because an
    unrelated transport was provisioned is both an outage for those users and
    long enough to time the API out mid-revoke."""

    driver = _driver(tmp_path)
    desired = _state("a")
    calls: list[str] = []
    monkeypatch.setattr(xray, "run_fixed_argv", _runner([], calls))

    await driver._apply_hysteria(desired)  # first apply writes and restarts
    assert calls == ["restart", "is-active"]

    calls.clear()
    await driver._apply_hysteria(desired)  # identical set: nothing to do
    assert calls == []


async def test_a_failed_restart_is_an_apply_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        xray, "run_fixed_argv", _runner([CompletedRun(1, b"", b"unit not found")], calls)
    )

    with pytest.raises(ApplyError, match="unit not found"):
        await driver._apply_hysteria(_state("a"))


async def test_activating_is_waited_out_rather_than_read_as_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`systemctl restart` returns as soon as the process is spawned, and
    is-active reports "activating" (exit 3) for a moment after. Checking once
    turned a healthy restart into apply_failed, and the client could not then
    be revoked -- the disconnect bug that withdrew v0.1.5."""

    driver = _driver(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(xray, "_HYSTERIA_ACTIVE_POLL_SECONDS", 0.0)
    monkeypatch.setattr(
        xray,
        "run_fixed_argv",
        _runner(
            [
                CompletedRun(0, b"", b""),  # restart
                CompletedRun(3, b"activating\n", b""),
                CompletedRun(3, b"activating\n", b""),
                CompletedRun(0, b"active\n", b""),
            ],
            calls,
        ),
    )

    await driver._apply_hysteria(_state("a"))

    assert calls.count("is-active") == 3, "must keep polling, not decide on the first answer"


async def test_a_failed_unit_gives_up_immediately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "failed" is terminal -- polling it to the timeout would just delay the
    error by fifteen seconds and hold the API's request open for them."""

    driver = _driver(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(xray, "_HYSTERIA_ACTIVE_POLL_SECONDS", 0.0)
    monkeypatch.setattr(
        xray,
        "run_fixed_argv",
        _runner([CompletedRun(0, b"", b""), CompletedRun(3, b"failed\n", b"")], calls),
    )

    with pytest.raises(ApplyError, match="did not come up: failed"):
        await driver._apply_hysteria(_state("a"))
    assert calls.count("is-active") == 1


async def test_a_unit_that_never_comes_up_times_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(xray, "_HYSTERIA_ACTIVE_POLL_SECONDS", 0.0)
    monkeypatch.setattr(xray, "_HYSTERIA_ACTIVE_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(
        xray,
        "run_fixed_argv",
        _runner([CompletedRun(0, b"", b""), CompletedRun(3, b"activating\n", b"")], calls),
    )

    with pytest.raises(ApplyError, match="did not come up"):
        await driver._apply_hysteria(_state("a"))


async def test_live_credentials_are_read_back_from_the_served_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reconciliation is only worth anything if it consults the file the server
    loads rather than this driver's own record of what it wrote."""

    driver = _driver(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(xray, "run_fixed_argv", _runner([], calls))
    desired = _state("a", "b")
    await driver._apply_hysteria(desired)

    live = driver._live_hysteria_uuids()

    assert live == {str(c.client_uuid) for c in desired.clients}


async def test_no_clients_renders_a_placeholder_rather_than_an_empty_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hysteria2 rejects both a bare `userpass:` key and an empty `{}` map, and
    a rejected config is what crash-looped the unit 25,126 times. Revoking the
    last client must still leave a startable server."""

    driver = _driver(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(xray, "run_fixed_argv", _runner([], calls))

    await driver._apply_hysteria(_state())

    # Written by the apply above; an async read here would only satisfy a rule
    # aimed at not blocking a real event loop.
    config_path = Path(str(driver._settings.xray_hysteria_config_file))
    text = config_path.read_text()  # noqa: ASYNC240
    assert "userpass:" in text
    assert "{}" not in text
    assert NO_CLIENTS_USER in text, "a placeholder entry must be present"
    # And it is not a credential anybody holds.
    assert driver._live_hysteria_uuids() == set()


async def test_the_placeholder_is_not_an_orphan_to_prune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read as a credential, the placeholder was one no database row accounts
    for, so every sweep's prune "removed" it by restarting Xray -- dropping
    every live connection on the server -- and the re-render wrote it back.
    Production did that every fifteen minutes."""

    driver = _driver(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(xray, "run_fixed_argv", _runner([], calls))
    await driver._apply_hysteria(_state())
    calls.clear()

    response = await driver.prune_clients(
        PruneXrayClientsRequest(correlation_id=uuid4(), expected=())
    )

    assert response.state == "pruned"
    assert response.removed == 0
    assert calls == [], "a prune with nothing to remove must not restart anything"
