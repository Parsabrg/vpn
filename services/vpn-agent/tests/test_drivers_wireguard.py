import base64
from collections.abc import Awaitable, Callable
from ipaddress import ip_address
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest

import nebula_agent.drivers.wireguard as wireguard
from nebula_agent.drivers._exec import CompletedRun
from nebula_agent.drivers.base import (
    DisableDeviceRequest,
    EnableDeviceRequest,
    HealthRequest,
    ProvisionDeviceRequest,
    ReconcileRequest,
    RevokeDeviceRequest,
)
from nebula_agent.drivers.config_store import ConfigStore, RenderedPeer
from nebula_agent.drivers.errors import ApplyError, RollbackFailedError, ValidationError
from nebula_agent.drivers.wireguard import (
    NativeWireGuardDriver,
    build_pubkey_argv,
    build_show_dump_argv,
    build_strip_argv,
    build_syncconf_argv,
    expected_allowed_ips,
    parse_show_dump,
    validate_address_in_client_pool,
)
from nebula_agent.settings import Settings

PUBLIC_KEY = base64.b64encode(bytes(range(1, 33))).decode()
FAKE_SERVER_PUBLIC_KEY = "server-pubkey-marker"

RunFixedArgv = Callable[..., Awaitable[CompletedRun]]


# --- pure argv builders -----------------------------------------------------


def test_build_pubkey_argv_uses_the_configured_binary() -> None:
    settings = Settings(env="test", wg_binary=PurePosixPath("/usr/bin/wg"))
    assert build_pubkey_argv(settings) == ["/usr/bin/wg", "pubkey"]


def test_build_strip_argv_uses_the_configured_wg_quick_binary(tmp_path: Path) -> None:
    settings = Settings(env="test", wg_quick_binary=PurePosixPath("/usr/bin/wg-quick"))
    candidate = tmp_path / "wg0.conf.candidate"
    assert build_strip_argv(settings, candidate) == [
        "/usr/bin/wg-quick",
        "strip",
        str(candidate),
    ]


def test_build_syncconf_argv_includes_the_interface_name(tmp_path: Path) -> None:
    settings = Settings(env="test", wg_interface="wg1")
    candidate = tmp_path / "wg1.conf.candidate"
    assert build_syncconf_argv(settings, candidate) == [
        "/usr/bin/wg",
        "syncconf",
        "wg1",
        str(candidate),
    ]


def test_build_show_dump_argv() -> None:
    settings = Settings(env="test", wg_interface="wg0")
    assert build_show_dump_argv(settings) == ["/usr/bin/wg", "show", "wg0", "dump"]


# --- validation --------------------------------------------------------------


def test_validate_address_in_client_pool_accepts_an_address_inside_the_pool() -> None:
    settings = Settings(env="test", wg_client_pool="10.77.0.0/24")
    peer = RenderedPeer(public_key=PUBLIC_KEY, assigned_address=ip_address("10.77.0.5"))
    validate_address_in_client_pool(settings, peer)  # does not raise


def test_validate_address_in_client_pool_rejects_an_address_outside_the_pool() -> None:
    settings = Settings(env="test", wg_client_pool="10.77.0.0/24")
    peer = RenderedPeer(public_key=PUBLIC_KEY, assigned_address=ip_address("10.99.0.5"))
    with pytest.raises(ValidationError, match="outside wg_client_pool"):
        validate_address_in_client_pool(settings, peer)


# --- wg show dump parsing -----------------------------------------------------


def test_parse_show_dump_extracts_peer_allowed_ips() -> None:
    output = (
        "private-key-marker\tserver-pubkey-marker\t51820\toff\n"
        f"{PUBLIC_KEY}\t(none)\t203.0.113.5:51820\t10.77.0.2/32\t0\t0\t0\toff\n"
    )
    peers = parse_show_dump(output)
    assert peers == {PUBLIC_KEY: "10.77.0.2/32"}


def test_parse_show_dump_with_no_peers_returns_empty() -> None:
    output = "private-key-marker\tserver-pubkey-marker\t51820\toff\n"
    assert parse_show_dump(output) == {}


def test_parse_show_dump_skips_blank_and_malformed_lines() -> None:
    output = (
        "private-key-marker\tserver-pubkey-marker\t51820\toff\n"
        "\n"
        "too\tshort\n"
        f"{PUBLIC_KEY}\t(none)\t203.0.113.5:51820\t10.77.0.2/32\t0\t0\t0\toff\n"
    )
    assert parse_show_dump(output) == {PUBLIC_KEY: "10.77.0.2/32"}


def test_expected_allowed_ips_uses_a_32_prefix_for_ipv4() -> None:
    assert expected_allowed_ips(ip_address("10.77.0.2")) == "10.77.0.2/32"


def test_expected_allowed_ips_uses_a_128_prefix_for_ipv6() -> None:
    assert expected_allowed_ips(ip_address("fd00::2")) == "fd00::2/128"


# --- NativeWireGuardDriver, with run_fixed_argv mocked ------------------------


def _driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> NativeWireGuardDriver:
    monkeypatch.setattr(Path, "read_bytes", lambda self: b"fake-private-key-bytes")
    settings = Settings(env="test", wg_client_pool="10.77.0.0/24")
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    return NativeWireGuardDriver(settings, store)


def _stub(responses: dict[str, CompletedRun]) -> RunFixedArgv:
    calls: list[str] = []

    async def _run(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        subcommand = argv[1]
        calls.append(subcommand)
        return responses[subcommand]

    _run.calls = calls  # type: ignore[attr-defined]
    return _run


def _provision_request(**overrides: object) -> ProvisionDeviceRequest:
    defaults: dict[str, object] = {
        "idempotency_key": uuid4(),
        "correlation_id": uuid4(),
        "target_kind": "wireguard_peer",
        "target_id": uuid4(),
        "desired_generation": 0,
        "public_key": PUBLIC_KEY,
        "assigned_address": "10.77.0.2",
    }
    defaults.update(overrides)
    return ProvisionDeviceRequest(**defaults)


@pytest.mark.anyio
async def test_provision_device_succeeds_when_every_subprocess_call_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub(
        {
            "pubkey": CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b""),
            "strip": CompletedRun(0, b"", b""),
            "syncconf": CompletedRun(0, b"", b""),
        }
    )
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.provision_device(_provision_request(desired_generation=5))

    assert response.state == "active"
    assert response.applied_generation == 5
    assert response.server_public_key == FAKE_SERVER_PUBLIC_KEY
    assert stub.calls == ["pubkey", "strip", "syncconf"]  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_server_public_key_is_derived_only_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub(
        {
            "pubkey": CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b""),
            "strip": CompletedRun(0, b"", b""),
            "syncconf": CompletedRun(0, b"", b""),
        }
    )
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    await driver.provision_device(_provision_request(public_key=PUBLIC_KEY))
    other_key = base64.b64encode(bytes(range(33, 65))).decode()
    await driver.provision_device(_provision_request(public_key=other_key))

    assert stub.calls.count("pubkey") == 1  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_provision_device_rejects_an_address_outside_the_client_pool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)

    with pytest.raises(ValidationError, match="outside wg_client_pool"):
        await driver.provision_device(_provision_request(assigned_address="10.99.0.2"))


@pytest.mark.anyio
async def test_provision_device_fails_when_validation_rejects_the_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub(
        {
            "pubkey": CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b""),
            "strip": CompletedRun(1, b"", b"malformed config"),
        }
    )
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.provision_device(_provision_request())

    assert response.state == "failed"
    # A rejected candidate is never applied.
    assert "syncconf" not in stub.calls  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_provision_device_rolls_back_when_apply_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    apply_calls = {"count": 0}

    async def _run(
        argv: list[str], *, timeout_seconds: float, stdin: bytes | None = None
    ) -> CompletedRun:
        subcommand = argv[1]
        if subcommand == "pubkey":
            return CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b"")
        if subcommand == "strip":
            return CompletedRun(0, b"", b"")
        if subcommand == "syncconf":
            apply_calls["count"] += 1
            # The first syncconf call is the real (failing) apply; the
            # second is the rollback re-apply of last-known-good, which
            # succeeds -- otherwise this couldn't distinguish "apply failed,
            # rollback recovered" from "apply failed, rollback also failed".
            if apply_calls["count"] == 1:
                return CompletedRun(1, b"", b"device busy")
            return CompletedRun(0, b"", b"")
        raise AssertionError(f"unexpected subcommand {subcommand!r}")

    monkeypatch.setattr(wireguard, "run_fixed_argv", _run)

    response = await driver.provision_device(_provision_request())

    assert response.state == "failed"
    # Once for the failed apply, once for the rollback re-apply of last-known-good.
    assert apply_calls["count"] == 2


@pytest.mark.anyio
async def test_provision_device_surfaces_rollback_failed_error_when_rollback_also_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed apply AND a failed rollback leaves the interface in an
    unknown state -- this must never be silently reported as a normal
    "failed" response; it has to propagate so it surfaces as unhealthy."""

    driver = _driver(tmp_path, monkeypatch)
    stub = _stub(
        {
            "pubkey": CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b""),
            "strip": CompletedRun(0, b"", b""),
            "syncconf": CompletedRun(1, b"", b"device busy"),
        }
    )
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    with pytest.raises(RollbackFailedError, match="device busy"):
        await driver.provision_device(_provision_request())


@pytest.mark.anyio
async def test_failed_provision_reports_the_peers_previous_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    ok = _stub(
        {
            "pubkey": CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b""),
            "strip": CompletedRun(0, b"", b""),
            "syncconf": CompletedRun(0, b"", b""),
        }
    )
    monkeypatch.setattr(wireguard, "run_fixed_argv", ok)
    await driver.provision_device(_provision_request(desired_generation=3))

    failing = _stub(
        {
            "pubkey": CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b""),
            "strip": CompletedRun(1, b"", b"bad"),
        }
    )
    monkeypatch.setattr(wireguard, "run_fixed_argv", failing)
    response = await driver.provision_device(_provision_request(desired_generation=4))

    assert response.state == "failed"
    assert response.applied_generation == 3


@pytest.mark.anyio
async def test_revoke_device_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub({"strip": CompletedRun(0, b"", b""), "syncconf": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.revoke_device(
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=2,
        )
    )
    assert response.state == "revoked"
    assert response.applied_generation == 2


@pytest.mark.anyio
async def test_revoke_device_reports_failure_when_validation_rejects_the_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub({"strip": CompletedRun(1, b"", b"malformed")})
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.revoke_device(
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=2,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"


@pytest.mark.anyio
async def test_enable_device_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub({"strip": CompletedRun(0, b"", b""), "syncconf": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.enable_device(
        EnableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=1,
        )
    )
    assert response.state == "enabled"


@pytest.mark.anyio
async def test_enable_device_reports_failure_when_validation_rejects_the_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub({"strip": CompletedRun(1, b"", b"malformed")})
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.enable_device(
        EnableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=1,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"


@pytest.mark.anyio
async def test_disable_device_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub({"strip": CompletedRun(0, b"", b""), "syncconf": CompletedRun(0, b"", b"")})
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.disable_device(
        DisableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=1,
        )
    )
    assert response.state == "disabled"


@pytest.mark.anyio
async def test_disable_device_reports_failure_when_validation_rejects_the_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub({"strip": CompletedRun(1, b"", b"malformed")})
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    response = await driver.disable_device(
        DisableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=1,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"


@pytest.mark.anyio
async def test_provision_device_surfaces_apply_error_when_pubkey_derivation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    stub = _stub({"pubkey": CompletedRun(1, b"", b"no such file")})
    monkeypatch.setattr(wireguard, "run_fixed_argv", stub)

    with pytest.raises(ApplyError, match="server public key"):
        await driver.provision_device(_provision_request())


@pytest.mark.anyio
async def test_health_reports_the_live_peer_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    dump = (
        "private-key-marker\tserver-pubkey-marker\t51820\toff\n"
        f"{PUBLIC_KEY}\t(none)\t203.0.113.5:51820\t10.77.0.2/32\t0\t0\t0\toff\n"
    )
    monkeypatch.setattr(
        wireguard, "run_fixed_argv", _stub({"show": CompletedRun(0, dump.encode(), b"")})
    )

    response = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert response.state == "healthy"
    assert response.interface_up is True
    assert response.peer_count == 1


@pytest.mark.anyio
async def test_health_reports_unreachable_when_show_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    monkeypatch.setattr(
        wireguard, "run_fixed_argv", _stub({"show": CompletedRun(1, b"", b"no such device")})
    )

    response = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert response.state == "unreachable"
    assert response.interface_up is False


@pytest.mark.anyio
async def test_reconcile_reports_in_sync_when_live_and_recorded_state_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    ok = _stub(
        {
            "pubkey": CompletedRun(0, FAKE_SERVER_PUBLIC_KEY.encode(), b""),
            "strip": CompletedRun(0, b"", b""),
            "syncconf": CompletedRun(0, b"", b""),
        }
    )
    monkeypatch.setattr(wireguard, "run_fixed_argv", ok)
    await driver.provision_device(_provision_request(desired_generation=6))

    dump = (
        "private-key-marker\tserver-pubkey-marker\t51820\toff\n"
        f"{PUBLIC_KEY}\t(none)\t203.0.113.5:51820\t10.77.0.2/32\t0\t0\t0\toff\n"
    )
    monkeypatch.setattr(
        wireguard, "run_fixed_argv", _stub({"show": CompletedRun(0, dump.encode(), b"")})
    )

    response = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=6,
        )
    )
    assert response.outcome == "in_sync"
    assert response.observed_generation == 6


@pytest.mark.anyio
async def test_reconcile_reports_drift_detected_when_peer_is_missing_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    dump = "private-key-marker\tserver-pubkey-marker\t51820\toff\n"
    monkeypatch.setattr(
        wireguard, "run_fixed_argv", _stub({"show": CompletedRun(0, dump.encode(), b"")})
    )

    response = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=1,
        )
    )
    assert response.outcome == "drift_detected"


@pytest.mark.anyio
async def test_reconcile_reports_ambiguous_when_show_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _driver(tmp_path, monkeypatch)
    monkeypatch.setattr(
        wireguard, "run_fixed_argv", _stub({"show": CompletedRun(1, b"", b"no such device")})
    )

    response = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=1,
        )
    )
    assert response.outcome == "ambiguous"
    assert response.error_code == "show_failed"
