import asyncio
import json
from collections.abc import Awaitable, Callable
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

import pytest

import nebula_agent.drivers.xray as xray
from nebula_agent.drivers._exec import CompletedRun
from nebula_agent.drivers.errors import ApplyError, RollbackFailedError, ValidationError
from nebula_agent.drivers.xray import (
    NativeXrayDriver,
    build_reload_argv,
    build_validate_argv,
)
from nebula_agent.drivers.xray_base import (
    ExpectedXrayClient,
    ProvisionXrayClientRequest,
    PruneXrayClientsRequest,
    ReconcileXrayClientRequest,
    RevokeXrayClientRequest,
    XrayHealthRequest,
)
from nebula_agent.drivers.xray_config_store import (
    DesiredXrayState,
    RenderedXrayClient,
    XrayConfigStore,
    XrayInboundProfile,
)
from nebula_agent.settings import Settings

RunFixedArgv = Callable[..., Awaitable[CompletedRun]]


# --- pure argv builders -----------------------------------------------------


def test_build_validate_argv_uses_the_configured_binary(tmp_path: Path) -> None:
    settings = Settings(env="test", xray_binary=PurePosixPath("/usr/local/bin/xray"))
    candidate = tmp_path / "config.json.validate"
    assert build_validate_argv(settings, candidate) == [
        "/usr/local/bin/xray",
        "run",
        "-test",
        "-config",
        str(candidate),
    ]


def test_build_reload_argv() -> None:
    assert build_reload_argv() == ["/usr/bin/systemctl", "restart", "nebula-xray"]


# --- NativeXrayDriver, with run_fixed_argv mocked ----------------------------


def _driver(tmp_path: Path) -> NativeXrayDriver:
    settings = Settings(env="test")
    store = XrayConfigStore(
        PurePosixPath(str(tmp_path / "state")), PurePosixPath(str(tmp_path / "config"))
    )
    return NativeXrayDriver(settings, store)


def _stub(responses: dict[str, CompletedRun]) -> RunFixedArgv:
    calls: list[str] = []

    async def _run(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        key = argv[1]
        calls.append(key)
        return responses[key]

    _run.calls = calls  # type: ignore[attr-defined]
    return _run


def _stub_failed_reload_then_successful_rollback() -> tuple[RunFixedArgv, dict[str, int]]:
    calls = {"restart": 0}

    async def _run(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        key = argv[1]
        if key == "run":
            return CompletedRun(0, b"", b"")
        if key == "restart":
            calls["restart"] += 1
            if calls["restart"] == 1:
                return CompletedRun(1, b"", b"reload rejected")
            return CompletedRun(0, b"", b"")
        raise AssertionError(f"unexpected subcommand {key!r}")

    return _run, calls


def _provision_request(**overrides: object) -> ProvisionXrayClientRequest:
    defaults: dict[str, object] = {
        "idempotency_key": uuid4(),
        "correlation_id": uuid4(),
        "target_kind": "xray_client",
        "target_id": uuid4(),
        "desired_generation": 0,
        "client_uuid": uuid4(),
        "protocol_profile_code": "vless-xhttp-tls",
    }
    defaults.update(overrides)
    return ProvisionXrayClientRequest(**defaults)


@pytest.mark.anyio
async def test_provision_client_succeeds_when_every_subprocess_call_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)

    response = await driver.provision_client(_provision_request(desired_generation=5))

    assert response.state == "active"
    assert response.applied_generation == 5
    # XHTTP is loopback-only and nginx-fronted, so the inbound's own security
    # is "none" -- but this field describes what the CLIENT dials, and the
    # client dials nginx over TLS. Reporting the inbound's value here is the
    # bug that left XHTTP advertising a loopback port with no encryption from
    # the day it was written; this assertion used to encode it.
    assert response.transport_security == "tls"
    assert stub.calls == ["run", "restart"]  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_provision_client_fails_without_reloading_when_validation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    stub = _stub({"run": CompletedRun(1, b"", b"malformed config")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)

    response = await driver.provision_client(_provision_request())

    assert response.state == "failed"
    assert response.error_code == "apply_failed"
    assert stub.calls == ["run"]  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_provision_client_rolls_back_when_reload_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    stub, calls = _stub_failed_reload_then_successful_rollback()
    monkeypatch.setattr(xray, "run_fixed_argv", stub)

    response = await driver.provision_client(_provision_request())

    assert response.state == "failed"
    assert response.error_code == "apply_failed"
    # Once for the failed apply's reload, once for the rollback re-apply.
    assert calls["restart"] == 2


@pytest.mark.anyio
async def test_provision_client_surfaces_rollback_failed_error_when_rollback_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(1, b"", b"unit busy")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)

    with pytest.raises(RollbackFailedError, match="unit busy"):
        await driver.provision_client(_provision_request())


@pytest.mark.anyio
async def test_failed_provision_reports_the_clients_previous_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    client_uuid = uuid4()
    ok = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", ok)
    await driver.provision_client(_provision_request(client_uuid=client_uuid, desired_generation=3))

    failing, _calls = _stub_failed_reload_then_successful_rollback()
    monkeypatch.setattr(xray, "run_fixed_argv", failing)
    response = await driver.provision_client(
        _provision_request(client_uuid=client_uuid, desired_generation=4)
    )

    assert response.state == "failed"
    assert response.applied_generation == 3


@pytest.mark.anyio
async def test_revoke_client_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _driver(tmp_path)
    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)

    response = await driver.revoke_client(
        RevokeXrayClientRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="xray_client",
            target_id=uuid4(),
            client_uuid=uuid4(),
            protocol_profile_code="vless-xhttp-tls",
            desired_generation=2,
        )
    )
    assert response.state == "revoked"
    assert response.applied_generation == 2


@pytest.mark.anyio
async def test_revoke_client_reports_failure_when_apply_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    stub, _calls = _stub_failed_reload_then_successful_rollback()
    monkeypatch.setattr(xray, "run_fixed_argv", stub)

    response = await driver.revoke_client(
        RevokeXrayClientRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="xray_client",
            target_id=uuid4(),
            client_uuid=uuid4(),
            protocol_profile_code="vless-xhttp-tls",
            desired_generation=2,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"


class _FakeWriter:
    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


@pytest.mark.anyio
async def test_health_reports_healthy_when_the_local_listener_accepts_a_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)

    async def fake_open_connection(host: str, port: int) -> tuple[object, _FakeWriter]:
        return object(), _FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    response = await driver.health(XrayHealthRequest(correlation_id=uuid4()))
    assert response.state == "healthy"
    assert response.listener_up is True
    assert response.client_count == 0


@pytest.mark.anyio
async def test_health_reports_unreachable_when_the_connection_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)

    async def fake_open_connection(host: str, port: int) -> tuple[object, _FakeWriter]:
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    response = await driver.health(XrayHealthRequest(correlation_id=uuid4()))
    assert response.state == "unreachable"
    assert response.listener_up is False
    assert response.error_code == "listener_unreachable"


# --- reconcile_client -------------------------------------------------------


def _reconcile_request(**overrides: object) -> ReconcileXrayClientRequest:
    defaults: dict[str, object] = {
        "correlation_id": uuid4(),
        "target_kind": "xray_client",
        "target_id": uuid4(),
        "desired_generation": 1,
        "client_uuid": uuid4(),
        "protocol_profile_code": "vless-xhttp-tls",
    }
    defaults.update(overrides)
    return ReconcileXrayClientRequest(**defaults)


async def _provisioned(
    driver: NativeXrayDriver, monkeypatch: pytest.MonkeyPatch, **kw: object
) -> ProvisionXrayClientRequest:
    """Drive a real provision so both views -- the config file and the
    bookkeeping state -- are populated the way the driver itself writes them,
    rather than hand-building fixtures that could drift from reality."""

    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)
    request = _provision_request(**kw)
    await driver.provision_client(request)
    return request


@pytest.mark.anyio
async def test_reconcile_reports_in_sync_when_both_views_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    provisioned = await _provisioned(driver, monkeypatch, desired_generation=3)

    response = await driver.reconcile_client(
        _reconcile_request(client_uuid=provisioned.client_uuid, desired_generation=3)
    )

    assert response.outcome == "in_sync"
    assert response.observed_generation == 3


@pytest.mark.anyio
async def test_reconcile_reports_drift_when_the_client_is_absent_from_both_views(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    await _provisioned(driver, monkeypatch)

    # A UUID that was never provisioned: absent from the config file and from
    # the bookkeeping state, so the two agree it is gone.
    response = await driver.reconcile_client(_reconcile_request())

    assert response.outcome == "drift_detected"
    assert response.observed_generation is None


@pytest.mark.anyio
async def test_reconcile_reports_ambiguous_when_the_two_views_disagree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bookkeeping says the client exists but the config Xray actually reads
    does not contain it -- an apply that landed in one place only. Revoking on
    that basis could destroy a live client, so the driver must refuse to
    guess."""

    driver = _driver(tmp_path)
    provisioned = await _provisioned(driver, monkeypatch)
    driver._config_store.xray_config_path.write_text(
        json.dumps({"inbounds": [{"port": 8446, "settings": {"clients": []}}]})
    )

    response = await driver.reconcile_client(
        _reconcile_request(client_uuid=provisioned.client_uuid)
    )

    assert response.outcome == "ambiguous"


@pytest.mark.anyio
async def test_reconcile_reports_ambiguous_when_the_config_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    provisioned = await _provisioned(driver, monkeypatch)
    driver._config_store.xray_config_path.write_text("{ not json")

    response = await driver.reconcile_client(
        _reconcile_request(client_uuid=provisioned.client_uuid)
    )

    assert response.outcome == "ambiguous"
    assert response.error_code == "config_unreadable"


@pytest.mark.anyio
async def test_reconcile_reports_ambiguous_for_a_profile_this_agent_does_not_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sweep must not crash on a row whose profile this agent no longer has
    configured -- unlike provision/revoke, which surface that as a 500."""

    driver = _driver(tmp_path)
    provisioned = await _provisioned(driver, monkeypatch)

    response = await driver.reconcile_client(
        _reconcile_request(
            client_uuid=provisioned.client_uuid, protocol_profile_code="not-configured"
        )
    )

    assert response.outcome == "ambiguous"


# --- prune_clients ----------------------------------------------------------


def _expected(*clients: UUID) -> PruneXrayClientsRequest:
    return PruneXrayClientsRequest(
        correlation_id=uuid4(),
        expected=tuple(
            ExpectedXrayClient(client_uuid=c, protocol_profile_code="vless-xhttp-tls")
            for c in clients
        ),
    )


@pytest.mark.anyio
async def test_prune_removes_clients_absent_from_the_expected_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    keep = await _provisioned(driver, monkeypatch)
    drop = await _provisioned(driver, monkeypatch)

    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)
    response = await driver.prune_clients(_expected(keep.client_uuid))

    assert response.state == "pruned"
    assert response.removed == 1
    assert response.kept == 1
    remaining = {c.client_uuid for c in driver._config_store.read_last_known_good().clients}
    assert remaining == {keep.client_uuid}
    assert drop.client_uuid not in remaining


@pytest.mark.anyio
async def test_prune_with_nothing_to_remove_does_not_restart_xray(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A routine sweep on a healthy server must not drop every live connection
    just to confirm there was nothing to prune."""

    driver = _driver(tmp_path)
    keep = await _provisioned(driver, monkeypatch)

    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)
    response = await driver.prune_clients(_expected(keep.client_uuid))

    assert response.state == "pruned"
    assert response.removed == 0
    assert response.kept == 1
    assert stub.calls == []  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_prune_removes_everything_for_an_empty_expected_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    await _provisioned(driver, monkeypatch)

    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)
    response = await driver.prune_clients(
        PruneXrayClientsRequest(correlation_id=uuid4(), expected=())
    )

    assert response.removed == 1
    assert driver._config_store.read_last_known_good().clients == ()


@pytest.mark.anyio
async def test_prune_reports_failure_and_keeps_state_when_the_apply_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path)
    keep = await _provisioned(driver, monkeypatch)
    await _provisioned(driver, monkeypatch)

    stub = _stub({"run": CompletedRun(1, b"", b"bad config")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)
    response = await driver.prune_clients(_expected(keep.client_uuid))

    assert response.state == "failed"
    assert response.error_code == "apply_failed"
    assert response.removed == 0
    # Nothing was promoted, so both clients survive rather than the set being
    # left half-pruned.
    assert len(driver._config_store.read_last_known_good().clients) == 2


def test_a_fronted_profile_reports_the_public_endpoint_not_the_inbound() -> None:
    """XHTTP binds loopback with nginx terminating TLS in front of it, so the
    client dials the public port over TLS and never sees the inbound's own port
    or its lack of encryption.

    Reporting the inbound's values sent clients to a loopback port that answers
    nothing -- measured live as zero packets on the public port while every
    directly-bound transport carried traffic.
    """

    # No filesystem needed: this exercises the pure response mapping, which
    # never touches the store.
    settings = Settings(env="test", xray_public_port=8445, xray_local_listen_port=8446)
    store = XrayConfigStore(
        PurePosixPath("/var/lib/nebula/xray"), PurePosixPath("/etc/nebula/xray")
    )
    fronted = XrayInboundProfile(
        protocol_profile_code="vless-xhttp-tls",
        transport="xhttp",
        listen="127.0.0.1",
        port=8446,
        security="none",
        xhttp_path="/xhttp",
    )
    direct = XrayInboundProfile(
        protocol_profile_code="vless-grpc-tls",
        transport="grpc",
        listen="0.0.0.0",  # noqa: S104 - deliberately public in this fixture
        port=8447,
        security="tls",
        grpc_service_name="grpc",
    )
    driver = NativeXrayDriver(settings, store, profiles=(fronted, direct))

    common = driver._response_common("vless-xhttp-tls")
    assert common["port"] == 8445
    assert common["transport_security"] == "tls"

    # A directly-bound inbound still reports its own port and security.
    common = driver._response_common("vless-grpc-tls")
    assert common["port"] == 8447
    assert common["transport_security"] == "tls"


@pytest.mark.anyio
async def test_prune_removes_a_client_injected_straight_into_the_served_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prune used to compare the caller's expected set against this
    driver's own bookkeeping, so a credential written directly into the file
    Xray reads -- by hand, or by a half-finished experiment -- appeared in
    neither side of the comparison and survived every sweep indefinitely.

    Injecting into the served config is the whole point of the test: any
    credential this driver wrote is in bookkeeping by construction, so nothing
    the driver itself can produce exercises this path.
    """

    driver = _driver(tmp_path)
    keep = await _provisioned(driver, monkeypatch)

    config_path = driver._config_store.xray_config_path
    config = json.loads(config_path.read_text())
    intruder = str(uuid4())
    for inbound in config["inbounds"]:
        clients = inbound.get("settings", {}).get("clients")
        if clients:
            clients.append({"id": intruder, "flow": ""})
            break
    config_path.write_text(json.dumps(config))

    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)
    response = await driver.prune_clients(_expected(keep.client_uuid))

    assert response.state == "pruned"
    assert response.removed == 1, "the injected credential must be counted as removed"
    # Re-rendered from bookkeeping, so the intruder is gone from the file the
    # server actually loads -- which is the only place it ever existed.
    assert intruder not in config_path.read_text()
    assert stub.calls == ["run", "restart"]  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_prune_still_skips_the_restart_when_the_served_config_agrees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The new check must not cost a restart on a healthy server: reading the
    served config is what makes the sweep trustworthy, and making it restart
    Xray every sweep would be a worse bug than the one it fixes."""

    driver = _driver(tmp_path)
    first = await _provisioned(driver, monkeypatch)
    second = await _provisioned(driver, monkeypatch)

    stub = _stub({"run": CompletedRun(0, b"", b""), "restart": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(xray, "run_fixed_argv", stub)
    response = await driver.prune_clients(_expected(first.client_uuid, second.client_uuid))

    assert response.state == "pruned"
    assert response.removed == 0
    assert stub.calls == []  # type: ignore[attr-defined]


# --- resyncing the served config on startup ---------------------------------
#
# Provisioning writes config only when the client set changes. Without a
# resync, a release that changes the config's *shape* -- the stats block and
# per-client emails that traffic accounting needs -- never takes effect: it
# waits for an unrelated user to provision, then activates at a moment nobody
# chose. That is how traffic accounting shipped and measured nothing.


def _ok(stdout: bytes = b"") -> CompletedRun:
    return CompletedRun(returncode=0, stdout=stdout, stderr=b"")


def _seeded_driver(tmp_path: Path) -> NativeXrayDriver:
    """A driver whose last-known-good names one client, and whose served
    config on disk is something this build would not render."""

    driver = _driver(tmp_path)
    desired = DesiredXrayState(
        clients=(
            RenderedXrayClient(
                client_uuid=uuid4(),
                protocol_profile_code="vless-xhttp-tls",
                generation=1,
            ),
        )
    )
    candidate = driver._config_store.write_candidate_atomically(
        driver._config_store.render_candidate(desired)
    )
    driver._config_store.promote_candidate_to_last_known_good(candidate)
    driver._config_store.write_xray_config_atomically('{"stale": true}')
    return driver


def test_resync_rewrites_a_served_config_that_does_not_match_this_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _seeded_driver(tmp_path)
    run = _stub({"run": _ok(), "restart": _ok()})
    monkeypatch.setattr(xray, "run_fixed_argv", run)

    assert asyncio.run(driver.resync_served_config()) is True

    served = json.loads(driver._config_store.xray_config_path.read_text())
    assert "stale" not in served
    # The shape the release actually needed, and could not previously deploy.
    assert served["stats"] == {}
    assert any(
        client.get("email")
        for inbound in served["inbounds"]
        for client in inbound.get("settings", {}).get("clients", [])
    )


def test_resync_does_nothing_when_the_served_config_already_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The common case: every restart. Reloading Xray anyway would drop every
    # live session on an agent restart that changed nothing.
    driver = _seeded_driver(tmp_path)
    run = _stub({"run": _ok(), "restart": _ok()})
    monkeypatch.setattr(xray, "run_fixed_argv", run)
    asyncio.run(driver.resync_served_config())

    run = _stub({"run": _ok(), "restart": _ok()})
    monkeypatch.setattr(xray, "run_fixed_argv", run)

    assert asyncio.run(driver.resync_served_config()) is False
    assert "restart" not in run.calls  # type: ignore[attr-defined]


def test_a_config_this_build_cannot_validate_never_reaches_the_live_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Validation runs against the store's scratch copy. A build that renders
    # something Xray rejects must leave the transport exactly as it was, not
    # overwrite a working config with a broken one.
    driver = _seeded_driver(tmp_path)
    before = driver._config_store.xray_config_path.read_text()
    run = _stub(
        {
            "run": CompletedRun(returncode=1, stdout=b"", stderr=b"bad config"),
            "restart": _ok(),
        }
    )
    monkeypatch.setattr(xray, "run_fixed_argv", run)

    with pytest.raises(ValidationError):
        asyncio.run(driver.resync_served_config())

    assert driver._config_store.xray_config_path.read_text() == before
    assert "restart" not in run.calls  # type: ignore[attr-defined]


def test_a_validated_config_that_will_not_load_is_put_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Validation passes but the unit fails to come up -- the case validation
    # cannot catch. The exact bytes that were being served go back, because
    # the alternative is an agent that starts with the transport down.
    driver = _seeded_driver(tmp_path)
    before = driver._config_store.xray_config_path.read_text()
    restarts = {"n": 0}

    async def _run(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        if argv[1] == "run":
            return _ok()
        restarts["n"] += 1
        # The first restart -- the new config -- fails; putting the old one
        # back succeeds.
        if restarts["n"] == 1:
            return CompletedRun(returncode=1, stdout=b"", stderr=b"unit failed")
        return _ok()

    monkeypatch.setattr(xray, "run_fixed_argv", _run)

    with pytest.raises(ApplyError):
        asyncio.run(driver.resync_served_config())

    assert driver._config_store.xray_config_path.read_text() == before
    assert restarts["n"] == 2


def test_resync_leaves_the_recorded_desired_state_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only the rendering moves. Nothing about which clients should exist
    # changed, so there is no new last-known-good to record -- and rewriting
    # it here would let a rendering bug quietly redefine what is provisioned.
    driver = _seeded_driver(tmp_path)
    before = driver._config_store.last_known_good_path.read_text()
    monkeypatch.setattr(xray, "run_fixed_argv", _stub({"run": _ok(), "restart": _ok()}))

    asyncio.run(driver.resync_served_config())

    assert driver._config_store.last_known_good_path.read_text() == before
