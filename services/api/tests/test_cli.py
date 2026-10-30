import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
import redis.asyncio as redis_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

import nebula_api.cli as cli_module
from nebula_api.access.expiry import ExpirySummary
from nebula_api.accounts.service import ActivationNotReissued
from nebula_api.cli import build_parser, main, read_password, run_seed_admin
from nebula_api.db.engine import SessionFactory
from nebula_api.provisioning.key_audit import CredentialKeyAudit
from nebula_api.provisioning.reconciliation import ReconciliationSummary
from nebula_api.retention import PruneSummary
from nebula_api.seed_admin import SeedAdminResult, SeedAdminStatus
from nebula_api.topology_seed import (
    EnableCapabilityResult,
    EnableCapabilityStatus,
    SeedProtocolResult,
    SeedProtocolStatus,
)
from nebula_api.usage.enforcement import EnforcementSummary
from nebula_api.usage.poll import UsagePollSummary
from nebula_api.usage.quota import QuotaChange
from nebula_api.usage.service import AccountUsage


def test_seed_parser_has_no_password_argument(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    canary = "canary-secret-that-must-not-be-reflected"

    with pytest.raises(SystemExit):
        parser.parse_args(["seed-admin", "--email", "admin@example.com", "--password", canary])

    assert canary not in capsys.readouterr().err


def test_password_entry_requires_interactive_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    with pytest.raises(RuntimeError, match="interactive terminal"):
        read_password()


def test_password_confirmation_must_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    responses = iter(["first-password", "second-password"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(responses))

    with pytest.raises(ValueError, match="confirmation"):
        read_password()


def test_password_confirmation_returns_hidden_value(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = "matching-canary-value"
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: candidate)

    assert read_password() == candidate


@pytest.mark.parametrize(
    ("status", "expected_output"),
    [
        (SeedAdminStatus.CREATED, "Created initial administrator"),
        (SeedAdminStatus.ALREADY_INITIALIZED, "already initialized"),
    ],
)
def test_run_seed_admin_disposes_engine_and_reports_generic_outcome(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: SeedAdminStatus,
    expected_output: str,
) -> None:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    session_factory = cast(SessionFactory, MagicMock())
    identifier = uuid4() if status is SeedAdminStatus.CREATED else None

    def fake_create_engine(_url: str, **_kwargs: object) -> AsyncEngine:
        return cast(AsyncEngine, engine)

    def fake_session_factory(_engine: AsyncEngine) -> SessionFactory:
        return session_factory

    seed = AsyncMock(return_value=SeedAdminResult(status=status, admin_id=identifier))
    monkeypatch.setattr(cli_module, "create_database_engine", fake_create_engine)
    monkeypatch.setattr(cli_module, "create_session_factory", fake_session_factory)
    monkeypatch.setattr(cli_module, "seed_initial_admin", seed)
    candidate = "canary-value-never-printed"

    result = asyncio.run(
        run_seed_admin(email="owner@example.com", username=None, password=candidate)
    )

    assert result == 0
    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert expected_output in output
    assert candidate not in output


@pytest.mark.parametrize(
    ("command", "run_function_name", "seed_function_name"),
    [
        ("seed-wireguard-protocol", "run_seed_wireguard_protocol", "seed_wireguard_protocol"),
        (
            "seed-vless-xhttp-protocol",
            "run_seed_vless_xhttp_protocol",
            "seed_vless_xhttp_protocol",
        ),
        ("seed-vless-grpc-protocol", "run_seed_vless_grpc_protocol", "seed_vless_grpc_protocol"),
        ("seed-vless-ws-protocol", "run_seed_vless_ws_protocol", "seed_vless_ws_protocol"),
        ("seed-vless-tcp-protocol", "run_seed_vless_tcp_protocol", "seed_vless_tcp_protocol"),
        ("seed-hysteria2-protocol", "run_seed_hysteria2_protocol", "seed_hysteria2_protocol"),
        (
            "seed-wireguard-adblock-profile",
            "run_seed_wireguard_adblock_profile",
            "seed_wireguard_adblock_profile",
        ),
        (
            "seed-vless-xhttp-adblock-protocol",
            "run_seed_vless_xhttp_adblock_protocol",
            "seed_vless_xhttp_adblock_protocol",
        ),
        (
            "seed-vless-grpc-adblock-protocol",
            "run_seed_vless_grpc_adblock_protocol",
            "seed_vless_grpc_adblock_protocol",
        ),
        (
            "seed-vless-ws-adblock-protocol",
            "run_seed_vless_ws_adblock_protocol",
            "seed_vless_ws_adblock_protocol",
        ),
        (
            "seed-vless-tcp-adblock-protocol",
            "run_seed_vless_tcp_adblock_protocol",
            "seed_vless_tcp_adblock_protocol",
        ),
        (
            "seed-hysteria2-adblock-protocol",
            "run_seed_hysteria2_adblock_protocol",
            "seed_hysteria2_adblock_protocol",
        ),
    ],
)
@pytest.mark.parametrize("status", [SeedProtocolStatus.CREATED, SeedProtocolStatus.ALREADY_SEEDED])
def test_run_seed_protocol_commands_dispose_engine_and_report_outcome(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    run_function_name: str,
    seed_function_name: str,
    status: SeedProtocolStatus,
) -> None:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    session_factory = cast(SessionFactory, MagicMock())
    result = SeedProtocolResult(status=status, protocol_id=uuid4(), protocol_profile_id=uuid4())

    def fake_create_engine(_url: str, **_kwargs: object) -> AsyncEngine:
        return cast(AsyncEngine, engine)

    def fake_session_factory(_engine: AsyncEngine) -> SessionFactory:
        return session_factory

    monkeypatch.setattr(cli_module, "create_database_engine", fake_create_engine)
    monkeypatch.setattr(cli_module, "create_session_factory", fake_session_factory)
    monkeypatch.setattr(cli_module, seed_function_name, AsyncMock(return_value=result))

    run_function = getattr(cli_module, run_function_name)
    assert asyncio.run(run_function()) == 0
    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert str(result.protocol_profile_id) in output


def test_main_dispatches_every_seed_protocol_command(monkeypatch: pytest.MonkeyPatch) -> None:
    for command, run_function_name in [
        ("seed-wireguard-protocol", "run_seed_wireguard_protocol"),
        ("seed-vless-xhttp-protocol", "run_seed_vless_xhttp_protocol"),
        ("seed-vless-grpc-protocol", "run_seed_vless_grpc_protocol"),
        ("seed-vless-ws-protocol", "run_seed_vless_ws_protocol"),
        ("seed-vless-tcp-protocol", "run_seed_vless_tcp_protocol"),
        ("seed-hysteria2-protocol", "run_seed_hysteria2_protocol"),
        ("seed-wireguard-adblock-profile", "run_seed_wireguard_adblock_profile"),
        ("seed-vless-xhttp-adblock-protocol", "run_seed_vless_xhttp_adblock_protocol"),
        ("seed-vless-grpc-adblock-protocol", "run_seed_vless_grpc_adblock_protocol"),
        ("seed-vless-ws-adblock-protocol", "run_seed_vless_ws_adblock_protocol"),
        ("seed-vless-tcp-adblock-protocol", "run_seed_vless_tcp_adblock_protocol"),
        ("seed-hysteria2-adblock-protocol", "run_seed_hysteria2_adblock_protocol"),
        ("seed-ss2022-protocol", "run_seed_ss2022_protocol"),
        ("seed-direct-protocols", "run_seed_direct_protocols"),
    ]:
        called = {"ran": False}

        async def fake_run(*, _called: dict[str, bool] = called) -> int:
            _called["ran"] = True
            return 0

        monkeypatch.setattr(cli_module, run_function_name, fake_run)
        assert main([command]) == 0
        assert called["ran"]


def test_main_dispatches_enable_server_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, str] = {}

    async def fake_run(*, server_code: str, protocol_profile_code: str) -> int:
        received.update(server_code=server_code, protocol_profile_code=protocol_profile_code)
        return 0

    monkeypatch.setattr(cli_module, "run_enable_server_capability", fake_run)

    assert (
        main(
            [
                "enable-server-capability",
                "--server-code",
                "vps-1",
                "--protocol-profile-code",
                "hysteria2",
            ]
        )
        == 0
    )
    assert received == {"server_code": "vps-1", "protocol_profile_code": "hysteria2"}


@pytest.mark.parametrize(
    ("status", "expected_output"),
    [
        (EnableCapabilityStatus.CREATED, "Enabled"),
        (EnableCapabilityStatus.ALREADY_ENABLED, "already enabled"),
        (EnableCapabilityStatus.RE_ENABLED, "Re-enabled"),
    ],
)
def test_run_enable_server_capability_disposes_engine_and_reports_outcome(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: EnableCapabilityStatus,
    expected_output: str,
) -> None:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    session_factory = cast(SessionFactory, MagicMock())
    result = EnableCapabilityResult(status=status, server_protocol_capability_id=uuid4())

    def fake_create_engine(_url: str, **_kwargs: object) -> AsyncEngine:
        return cast(AsyncEngine, engine)

    def fake_session_factory(_engine: AsyncEngine) -> SessionFactory:
        return session_factory

    monkeypatch.setattr(cli_module, "create_database_engine", fake_create_engine)
    monkeypatch.setattr(cli_module, "create_session_factory", fake_session_factory)
    monkeypatch.setattr(cli_module, "enable_server_capability", AsyncMock(return_value=result))

    from nebula_api.cli import run_enable_server_capability

    assert (
        asyncio.run(
            run_enable_server_capability(server_code="vps-1", protocol_profile_code="hysteria2")
        )
        == 0
    )
    engine.dispose.assert_awaited_once_with()
    assert expected_output in capsys.readouterr().out


def test_main_never_accepts_password_option(capsys: pytest.CaptureFixture[str]) -> None:
    canary = "second-canary-secret-that-must-not-be-reflected"

    with pytest.raises(SystemExit):
        main(["seed-admin", "--email", "admin@example.com", "--password", canary])

    assert canary not in capsys.readouterr().err


def test_main_runs_seed_without_reflecting_password(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = "main-canary-value"
    received: dict[str, str | None] = {}

    async def fake_run_seed_admin(*, email: str, username: str | None, password: str) -> int:
        received.update(email=email, username=username, password=password)
        return 0

    monkeypatch.setattr(cli_module, "read_password", lambda: candidate)
    monkeypatch.setattr(cli_module, "run_seed_admin", fake_run_seed_admin)

    assert main(["seed-admin", "--email", "owner@example.com"]) == 0
    assert received == {
        "email": "owner@example.com",
        "username": None,
        "password": candidate,
    }


def test_main_redacts_database_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    detail = "database-canary-detail"

    async def failing_seed(*, email: str, username: str | None, password: str) -> int:
        del email, username, password
        raise SQLAlchemyError(detail)

    monkeypatch.setattr(cli_module, "read_password", lambda: "hidden-canary-value")
    monkeypatch.setattr(cli_module, "run_seed_admin", failing_seed)

    with pytest.raises(SystemExit):
        main(["seed-admin", "--email", "owner@example.com"])

    error = capsys.readouterr().err
    assert "database operation failed" in error
    assert detail not in error


def test_main_redacts_invalid_database_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    canary = "malformed-database-url-with-cli-canary"
    monkeypatch.setenv("NEBULA_DATABASE_URL", canary)
    monkeypatch.setattr(cli_module, "read_password", lambda: "hidden-canary-value")

    with pytest.raises(SystemExit):
        main(["seed-admin", "--email", "owner@example.com"])

    assert canary not in capsys.readouterr().err


def test_generate_jwt_signing_key_writes_a_valid_matching_keypair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private_path = tmp_path / "jwt-private.pem"
    public_path = tmp_path / "jwt-public.pem"

    result = main(
        [
            "generate-jwt-signing-key",
            "--private-key-out",
            str(private_path),
            "--public-key-out",
            str(public_path),
        ]
    )

    assert result == 0
    private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    assert isinstance(private_key, Ed25519PrivateKey)
    assert isinstance(public_key, Ed25519PublicKey)
    raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert private_key.public_key().public_bytes(*raw) == public_key.public_bytes(*raw)
    output = capsys.readouterr().out
    assert str(private_path) in output
    assert str(public_path) in output
    assert "PRIVATE KEY" not in output


def test_generate_jwt_signing_key_refuses_to_overwrite_an_existing_file(tmp_path: Path) -> None:
    private_path = tmp_path / "jwt-private.pem"
    public_path = tmp_path / "jwt-public.pem"
    private_path.write_bytes(b"pre-existing-canary")

    with pytest.raises(SystemExit):
        main(
            [
                "generate-jwt-signing-key",
                "--private-key-out",
                str(private_path),
                "--public-key-out",
                str(public_path),
            ]
        )

    assert private_path.read_bytes() == b"pre-existing-canary"
    assert not public_path.exists()


@pytest.mark.parametrize("purpose", ["token-pepper", "mfa-encryption", "xray-encryption"])
def test_generate_symmetric_key_writes_exactly_32_random_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], purpose: str
) -> None:
    out_path = tmp_path / "generated-key"

    result = main(["generate-symmetric-key", "--purpose", purpose, "--out", str(out_path)])

    assert result == 0
    generated = out_path.read_bytes()
    assert len(generated) == 32
    output = capsys.readouterr().out
    assert str(out_path) in output
    assert generated.hex() not in output


def test_generate_symmetric_key_refuses_to_overwrite_an_existing_file(tmp_path: Path) -> None:
    out_path = tmp_path / "generated-key"
    out_path.write_bytes(b"pre-existing-canary-32-bytes!!!")

    with pytest.raises(SystemExit):
        main(["generate-symmetric-key", "--purpose", "token-pepper", "--out", str(out_path)])

    assert out_path.read_bytes() == b"pre-existing-canary-32-bytes!!!"


def test_reconcile_xray_is_an_available_command() -> None:
    """The pass is only reachable through this command (and whatever schedules
    it), so a missing subparser would silently mean nothing ever reconciles."""

    arguments = build_parser().parse_args(["reconcile-xray"])
    assert arguments.command == "reconcile-xray"


def _collect_usage_summary(**overrides: object) -> UsagePollSummary:
    defaults: dict[str, object] = dict(
        servers_polled=2,
        servers_failed=0,
        samples=7,
        credentials_active=3,
        sources_failed=[],
    )
    defaults.update(overrides)
    return UsagePollSummary(**defaults)  # type: ignore[arg-type]


def _patch_collect_usage_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    summary: UsagePollSummary,
    enforcement: EnforcementSummary | None = None,
    *,
    awaiting_removal: bool = False,
) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock()

    monkeypatch.setattr(
        cli_module, "create_database_engine", lambda _url, **_kwargs: cast(AsyncEngine, engine)
    )
    monkeypatch.setattr(
        cli_module, "create_session_factory", lambda _engine: cast(SessionFactory, MagicMock())
    )
    monkeypatch.setattr(cli_module, "load_auth_key_material", lambda _settings: MagicMock())
    monkeypatch.setattr(cli_module, "run_usage_poll", AsyncMock(return_value=summary))
    # Enforcement runs on the same totals the poll just wrote; it has its
    # own tests, and leaving it live here would drive a mocked session.
    monkeypatch.setattr(
        cli_module,
        "enforce_traffic_quotas",
        AsyncMock(return_value=enforcement or EnforcementSummary()),
    )
    monkeypatch.setattr(
        cli_module, "enforce_access_expiry", AsyncMock(return_value=ExpirySummary())
    )
    monkeypatch.setattr(
        cli_module, "credentials_awaiting_removal", AsyncMock(return_value=awaiting_removal)
    )
    # Anything waiting to be removed is taken off the servers in the same run.
    # Real reconciliation would drive the mocked session; the tests about that
    # replace these with their own.
    monkeypatch.setattr(cli_module, "_agents_keeping_counters", lambda _s, _e: object())
    monkeypatch.setattr(
        cli_module, "run_reconciliation", AsyncMock(return_value=ReconciliationSummary())
    )
    monkeypatch.setattr(
        cli_module, "run_xray_reconciliation", AsyncMock(return_value=ReconciliationSummary())
    )
    return engine


def test_run_collect_usage_reports_the_poll_and_disposes_the_engine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())

    assert asyncio.run(cli_module.run_collect_usage()) == 0

    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert "Polled 2 server(s), 0 unreachable" in output
    assert "7 sample(s), 3 credential(s) active" in output


def test_run_collect_usage_exits_non_zero_when_a_server_was_unreachable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The timer that runs this treats a non-zero exit as the signal worth
    # alerting on. A poll that quietly skipped a server would otherwise look
    # exactly like a poll where nobody used any traffic.
    _patch_collect_usage_dependencies(
        monkeypatch, _collect_usage_summary(servers_polled=1, servers_failed=1)
    )

    assert asyncio.run(cli_module.run_collect_usage()) == 1
    assert "1 unreachable" in capsys.readouterr().out


def test_run_collect_usage_names_the_sources_it_could_not_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Every server runs the same three engines, so "hysteria2" on its own
    # would not say which one went unread.
    _patch_collect_usage_dependencies(
        monkeypatch, _collect_usage_summary(sources_failed=["vps-1:hysteria2"])
    )

    assert asyncio.run(cli_module.run_collect_usage()) == 1
    assert "Sources that could not be read: vps-1:hysteria2" in capsys.readouterr().out


def test_a_spent_allowance_is_taken_off_the_servers_in_the_same_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Enforcement only marks credentials for removal. Leaving the removal to
    # the fifteen-minute sweep kept a spent account connected for another
    # sixteen minutes on the production server.
    _patch_collect_usage_dependencies(
        monkeypatch,
        _collect_usage_summary(),
        EnforcementSummary(accounts_checked=1, accounts_exhausted=1, credentials_revoked=2),
        awaiting_removal=True,
    )
    agents = object()
    monkeypatch.setattr(cli_module, "_agents_keeping_counters", lambda _s, _e: agents)
    wireguard = AsyncMock(return_value=ReconciliationSummary(checked=0))
    xray = AsyncMock(return_value=ReconciliationSummary(checked=2, repaired=2))
    monkeypatch.setattr(cli_module, "run_reconciliation", wireguard)
    monkeypatch.setattr(cli_module, "run_xray_reconciliation", xray)

    assert asyncio.run(cli_module.run_collect_usage()) == 0

    assert wireguard.await_args is not None and wireguard.await_args.args[1] is agents
    assert xray.await_args is not None and xray.await_args.args[1] is agents
    output = capsys.readouterr().out
    assert "Taken off the servers now: 2 credential(s), 0 failed." in output


def test_a_removal_that_failed_is_a_failed_run(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_collect_usage_dependencies(
        monkeypatch,
        _collect_usage_summary(),
        EnforcementSummary(accounts_checked=1, accounts_exhausted=1, credentials_revoked=1),
        awaiting_removal=True,
    )
    monkeypatch.setattr(cli_module, "_agents_keeping_counters", lambda _s, _e: object())
    monkeypatch.setattr(
        cli_module, "run_reconciliation", AsyncMock(return_value=ReconciliationSummary())
    )
    monkeypatch.setattr(
        cli_module,
        "run_xray_reconciliation",
        AsyncMock(return_value=ReconciliationSummary(checked=1, repair_failed=1)),
    )

    assert asyncio.run(cli_module.run_collect_usage()) == 1


def test_nothing_is_reconciled_when_nothing_is_waiting_to_be_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The run happens every minute; a full sweep each time would be waste.
    _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    wireguard = AsyncMock()
    xray = AsyncMock()
    monkeypatch.setattr(cli_module, "run_reconciliation", wireguard)
    monkeypatch.setattr(cli_module, "run_xray_reconciliation", xray)

    assert asyncio.run(cli_module.run_collect_usage()) == 0

    wireguard.assert_not_awaited()
    xray.assert_not_awaited()


def test_an_admin_revocation_is_taken_off_the_servers_by_the_next_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Nothing ran out in this run; an admin revoked a device a moment ago and
    # left its credentials REVOKING. They should not wait for the sweep.
    _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary(), awaiting_removal=True)
    xray = AsyncMock(return_value=ReconciliationSummary(checked=1, repaired=1))
    monkeypatch.setattr(cli_module, "run_xray_reconciliation", xray)

    assert asyncio.run(cli_module.run_collect_usage()) == 0

    xray.assert_awaited_once()


def test_lapsed_access_is_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    monkeypatch.setattr(
        cli_module,
        "enforce_access_expiry",
        AsyncMock(
            return_value=ExpirySummary(credentials_revoked=3, account_ids=[uuid4(), uuid4()])
        ),
    )

    asyncio.run(cli_module.run_collect_usage())

    assert "Ended lapsed access: 3 credential(s) across 2 account(s)." in capsys.readouterr().out


def test_run_collect_usage_disposes_the_engine_even_when_the_poll_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    monkeypatch.setattr(cli_module, "run_usage_poll", AsyncMock(side_effect=RuntimeError("boom")))

    with pytest.raises(RuntimeError):
        asyncio.run(cli_module.run_collect_usage())

    engine.dispose.assert_awaited_once_with()


def test_main_dispatches_collect_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"ran": False}

    async def fake_run() -> int:
        called["ran"] = True
        return 0

    monkeypatch.setattr(cli_module, "run_collect_usage", fake_run)

    assert main(["collect-usage"]) == 0
    assert called["ran"]


def _loop_polls(
    monkeypatch: pytest.MonkeyPatch,
    stop: asyncio.Event,
    *steps: object,
) -> AsyncMock:
    """Makes each poll take the next step, and stops the loop after the last.

    A step is a summary to return, an exception to raise, or "hang".
    """

    remaining = list(steps)

    async def poll(*_args: object) -> UsagePollSummary:
        step = remaining.pop(0)
        if not remaining:
            stop.set()
        if step == "hang":
            await asyncio.sleep(30)
        if isinstance(step, BaseException):
            raise step
        return cast(UsagePollSummary, step)

    mock = AsyncMock(side_effect=poll)
    monkeypatch.setattr(cli_module, "run_usage_poll", mock)
    return mock


def _heartbeat(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    beat = tmp_path / "nebula-usage-pass"
    monkeypatch.setattr(cli_module, "USAGE_HEARTBEAT", beat)
    return beat


def test_the_loop_runs_passes_until_stopped_and_stays_quiet(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # Every fifteen seconds is thousands of passes a day; a line each would
    # bury the ones that matter.
    engine = _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    beat = _heartbeat(monkeypatch, tmp_path)
    stop = asyncio.Event()
    summary = _collect_usage_summary()
    polls = _loop_polls(monkeypatch, stop, summary, summary, summary)

    assert asyncio.run(cli_module.run_collect_usage_every(0.01, stop=stop)) == 0

    assert polls.await_count == 3
    assert beat.exists()
    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert "Collecting usage every 0.01 seconds." in output
    assert "Polled" not in output


def test_the_loop_reports_a_pass_that_cut_somebody_off(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _patch_collect_usage_dependencies(
        monkeypatch,
        _collect_usage_summary(),
        EnforcementSummary(accounts_checked=1, accounts_exhausted=1, credentials_revoked=1),
        awaiting_removal=True,
    )
    _heartbeat(monkeypatch, tmp_path)
    stop = asyncio.Event()
    _loop_polls(monkeypatch, stop, _collect_usage_summary())

    asyncio.run(cli_module.run_collect_usage_every(0.01, stop=stop))

    output = capsys.readouterr().out
    assert "Revoked 1 credential(s) across 1 account(s)" in output
    assert "Taken off the servers now:" in output


def test_the_loop_reports_a_pass_that_could_not_read_a_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    _heartbeat(monkeypatch, tmp_path)
    stop = asyncio.Event()
    _loop_polls(monkeypatch, stop, _collect_usage_summary(sources_failed=["vps-1:hysteria2"]))

    asyncio.run(cli_module.run_collect_usage_every(0.01, stop=stop))

    assert "Sources that could not be read: vps-1:hysteria2" in capsys.readouterr().out


def test_a_failed_pass_does_not_end_the_loop_or_print_its_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # A database outage should not take enforcement down with it once the
    # database is back. The message stays out of the log: a driver's can
    # carry the connection string.
    _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    beat = _heartbeat(monkeypatch, tmp_path)
    stop = asyncio.Event()
    polls = _loop_polls(
        monkeypatch,
        stop,
        RuntimeError("postgresql://app:hunter2@postgres/nebula"),
        _collect_usage_summary(),
    )

    assert asyncio.run(cli_module.run_collect_usage_every(0.01, stop=stop)) == 0

    assert polls.await_count == 2
    assert beat.exists()
    output = capsys.readouterr().out
    assert "A usage pass failed: RuntimeError." in output
    assert "hunter2" not in output


def test_a_pass_that_never_finishes_is_abandoned(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    beat = _heartbeat(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_module, "USAGE_PASS_BUDGET_SECONDS", 0.05)
    stop = asyncio.Event()
    _loop_polls(monkeypatch, stop, "hang")

    asyncio.run(cli_module.run_collect_usage_every(0.01, stop=stop))

    # No finished pass, so nothing tells the health check this one is well.
    assert not beat.exists()
    assert "A usage pass took over 0.05s and was abandoned." in capsys.readouterr().out


def test_the_loop_says_it_is_still_running_now_and_then(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    _heartbeat(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_module, "USAGE_REPORT_SECONDS", 0.02)
    stop = asyncio.Event()
    summary = _collect_usage_summary()
    _loop_polls(monkeypatch, stop, RuntimeError("boom"), summary, summary, summary)

    asyncio.run(cli_module.run_collect_usage_every(0.01, stop=stop))

    output = capsys.readouterr().out
    assert "Collected usage 2 time(s), 1 failed." in output
    assert "Collected usage 2 time(s), 0 failed." in output


def test_the_loop_stops_on_a_signal_when_given_no_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _patch_collect_usage_dependencies(monkeypatch, _collect_usage_summary())
    stopped = asyncio.Event()
    stopped.set()
    monkeypatch.setattr(cli_module, "_stop_on_signals", lambda _loop: stopped)
    polls = AsyncMock()
    monkeypatch.setattr(cli_module, "run_usage_poll", polls)

    assert asyncio.run(cli_module.run_collect_usage_every(15)) == 0

    polls.assert_not_awaited()
    engine.dispose.assert_awaited_once_with()


@pytest.mark.skipif(sys.platform == "win32", reason="no event loop signal handlers on Windows")
def test_sigterm_sets_the_stop_event() -> None:
    # `docker stop` sends SIGTERM to the container's first process, and this
    # loop is that process.
    import os
    import signal

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        stop = cli_module._stop_on_signals(loop)
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(stop.wait(), timeout=2)
        finally:
            loop.remove_signal_handler(signal.SIGTERM)
            loop.remove_signal_handler(signal.SIGINT)

    asyncio.run(scenario())


def test_main_runs_the_loop_when_given_an_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[float] = []

    async def fake_loop(seconds: float) -> int:
        seen.append(seconds)
        return 0

    monkeypatch.setattr(cli_module, "run_collect_usage_every", fake_loop)

    assert main(["collect-usage", "--every", "15"]) == 0
    assert seen == [15.0]


@pytest.mark.parametrize("value", ["4.9", "0", "-15", "nan", "soon"])
def test_collect_usage_refuses_an_interval_it_cannot_keep(value: str) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["collect-usage", "--every", value])


def _patch_quota_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    change: QuotaChange,
    usage: AccountUsage,
) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock()

    monkeypatch.setattr(
        cli_module, "create_database_engine", lambda _url, **_kwargs: cast(AsyncEngine, engine)
    )
    monkeypatch.setattr(
        cli_module, "create_session_factory", lambda _engine: cast(SessionFactory, MagicMock())
    )
    monkeypatch.setattr(cli_module, "load_auth_key_material", lambda _settings: MagicMock())
    monkeypatch.setattr(cli_module, "set_traffic_quota", AsyncMock(return_value=change))

    service = MagicMock()
    service.usage_for_user = AsyncMock(return_value=usage)
    monkeypatch.setattr(cli_module, "UsageService", lambda *_args, **_kwargs: service)
    return engine


def _change(
    previous: int | None,
    quota: int | None,
    *,
    previous_used: int = 0,
    restored: bool = False,
) -> QuotaChange:
    return QuotaChange(
        user_id=uuid4(),
        email="owner@example.org",
        previous_bytes=previous,
        quota_bytes=quota,
        previous_used_bytes=previous_used,
        restored_access=restored,
    )


def test_set_traffic_quota_reports_the_old_and_new_allowance(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    gigabyte = 1024**3
    engine = _patch_quota_dependencies(
        monkeypatch,
        _change(previous=None, quota=100 * gigabyte),
        AccountUsage(rx_bytes=gigabyte, tx_bytes=gigabyte, quota_bytes=100 * gigabyte),
    )

    result = asyncio.run(
        cli_module.run_set_traffic_quota(email="owner@example.org", quota="100GB", unmetered=False)
    )

    assert result == 0
    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert "was:  unmetered (no limit)" in output
    assert "100.0 GB" in output
    assert "2.0 GB" in output


def test_set_traffic_quota_spells_out_zero_so_it_is_not_read_as_unmetered(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # "0 B" beside "unmetered" is one glance away from being read as the same
    # thing, and they are opposites.
    _patch_quota_dependencies(
        monkeypatch,
        _change(previous=None, quota=0),
        AccountUsage(rx_bytes=0, tx_bytes=0, quota_bytes=0),
    )

    asyncio.run(
        cli_module.run_set_traffic_quota(email="owner@example.org", quota="0B", unmetered=False)
    )

    output = capsys.readouterr().out
    assert "metered at zero, nothing allowed" in output


def test_set_traffic_quota_reports_what_the_previous_allowance_had_spent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A grant resets the count, so the figure being written off is the one
    # worth printing -- an operator who tops somebody up mid-plan should see
    # what they just forgave.
    gigabyte = 1024**3
    _patch_quota_dependencies(
        monkeypatch,
        _change(previous=gigabyte, quota=200 * gigabyte, previous_used=40 * gigabyte),
        AccountUsage(rx_bytes=0, tx_bytes=0, quota_bytes=200 * gigabyte),
    )

    asyncio.run(
        cli_module.run_set_traffic_quota(email="owner@example.org", quota="200GB", unmetered=False)
    )

    output = capsys.readouterr().out
    assert "the previous allowance had used 40.0 GB" in output


def test_set_traffic_quota_says_when_it_restored_access(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The point of a top-up for an account that ran out.
    gigabyte = 1024**3
    _patch_quota_dependencies(
        monkeypatch,
        _change(previous=gigabyte, quota=200 * gigabyte, restored=True),
        AccountUsage(rx_bytes=0, tx_bytes=0, quota_bytes=200 * gigabyte),
    )

    asyncio.run(
        cli_module.run_set_traffic_quota(email="owner@example.org", quota="200GB", unmetered=False)
    )

    assert "it can connect again" in capsys.readouterr().out


def test_set_traffic_quota_does_not_warn_for_an_unmetered_account(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # remaining_bytes is None when unmetered, and None must not be mistaken
    # for "nothing left".
    _patch_quota_dependencies(
        monkeypatch,
        _change(previous=1024**3, quota=None),
        AccountUsage(rx_bytes=99 * 1024**3, tx_bytes=0, quota_bytes=None),
    )

    asyncio.run(
        cli_module.run_set_traffic_quota(email="owner@example.org", quota=None, unmetered=True)
    )

    output = capsys.readouterr().out
    assert "now:  unmetered (no limit)" in output
    assert "already used" not in output


def test_main_dispatches_set_traffic_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, object] = {}

    async def fake_run(*, email: str, quota: str | None, unmetered: bool) -> int:
        received.update(email=email, quota=quota, unmetered=unmetered)
        return 0

    monkeypatch.setattr(cli_module, "run_set_traffic_quota", fake_run)

    assert main(["set-traffic-quota", "--email", "owner@example.org", "--quota", "100GB"]) == 0
    assert received == {"email": "owner@example.org", "quota": "100GB", "unmetered": False}


def test_an_allowance_must_be_given_one_way_or_the_other(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Neither flag would have to mean either unmetered or zero, and those are
    # opposites -- so argparse refuses rather than the code choosing.
    with pytest.raises(SystemExit):
        main(["set-traffic-quota", "--email", "owner@example.org"])

    assert "one of the arguments" in capsys.readouterr().err


def test_an_allowance_cannot_be_both_a_number_and_unmetered(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "set-traffic-quota",
                "--email",
                "owner@example.org",
                "--quota",
                "100GB",
                "--unmetered",
            ]
        )

    assert "not allowed with" in capsys.readouterr().err


def _patch_key_audit(monkeypatch: pytest.MonkeyPatch, audit: CredentialKeyAudit) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    monkeypatch.setattr(
        cli_module, "create_database_engine", lambda _url, **_kwargs: cast(AsyncEngine, engine)
    )
    monkeypatch.setattr(
        cli_module, "create_session_factory", lambda _engine: cast(SessionFactory, MagicMock())
    )
    monkeypatch.setattr(cli_module, "load_auth_key_material", lambda _settings: MagicMock())
    monkeypatch.setattr(cli_module, "audit_credential_keys", AsyncMock(return_value=audit))
    return engine


def test_audit_credential_keys_exits_zero_when_everything_opens(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = _patch_key_audit(
        monkeypatch,
        CredentialKeyAudit(readable=5, fingerprints_by_version={"1": {"abc"}}),
    )

    assert asyncio.run(cli_module.run_audit_credential_keys(mark_lost=False)) == 0
    engine.dispose.assert_awaited_once_with()
    assert "Readable:            5" in capsys.readouterr().out


def test_audit_credential_keys_exits_non_zero_when_something_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_key_audit(monkeypatch, CredentialKeyAudit(readable=5, unreadable=14))

    assert asyncio.run(cli_module.run_audit_credential_keys(mark_lost=False)) == 1
    assert "Re-run with --mark-lost" in capsys.readouterr().out


def test_audit_credential_keys_names_a_version_that_used_two_keys(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The finding the fingerprint exists to make: a key replaced without its
    # version changing, stated rather than deduced from file timestamps.
    _patch_key_audit(
        monkeypatch,
        CredentialKeyAudit(readable=2, fingerprints_by_version={"1": {"aaa", "bbb"}}),
    )

    asyncio.run(cli_module.run_audit_credential_keys(mark_lost=False))

    output = capsys.readouterr().out
    assert "More than one key has been used under version 1" in output
    assert "replaced without its version changing" in output


def test_audit_credential_keys_reports_what_it_marked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_key_audit(monkeypatch, CredentialKeyAudit(unreadable=14, marked_now=14))

    asyncio.run(cli_module.run_audit_credential_keys(mark_lost=True))

    output = capsys.readouterr().out
    assert "Marked lost just now: 14" in output
    assert "Re-run with --mark-lost" not in output


def test_main_dispatches_audit_credential_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, object] = {}

    async def fake_run(*, mark_lost: bool) -> int:
        received["mark_lost"] = mark_lost
        return 0

    monkeypatch.setattr(cli_module, "run_audit_credential_keys", fake_run)

    assert main(["audit-credential-keys"]) == 0
    assert received == {"mark_lost": False}
    assert main(["audit-credential-keys", "--mark-lost"]) == 0
    assert received == {"mark_lost": True}


def test_collect_usage_reports_accounts_it_cut_off(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Revoking somebody's access is not a silent side effect of a poll.
    _patch_collect_usage_dependencies(
        monkeypatch,
        _collect_usage_summary(),
        EnforcementSummary(accounts_exhausted=2, credentials_revoked=5),
    )

    asyncio.run(cli_module.run_collect_usage())

    output = capsys.readouterr().out
    assert "Revoked 5 credential(s) across 2 account(s)" in output


def test_collect_usage_says_how_many_are_still_cut_off(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Already-enforced accounts are not re-revoked, so without this line a
    # poll would say nothing at all about accounts currently without service.
    _patch_collect_usage_dependencies(
        monkeypatch, _collect_usage_summary(), EnforcementSummary(already_enforced=3)
    )

    asyncio.run(cli_module.run_collect_usage())

    assert "Still cut off: 3 account(s)." in capsys.readouterr().out


def _patch_initialize(
    monkeypatch: pytest.MonkeyPatch,
    *,
    deployment: object,
    created_deployment: bool,
    created_secret: bool,
    has_admin: bool,
) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    monkeypatch.setattr(
        cli_module, "create_database_engine", lambda _url, **_kwargs: cast(AsyncEngine, engine)
    )
    monkeypatch.setattr(
        cli_module, "create_session_factory", lambda _engine: cast(SessionFactory, MagicMock())
    )
    monkeypatch.setattr(
        cli_module,
        "ensure_deployment",
        AsyncMock(return_value=(deployment, created_deployment)),
    )
    monkeypatch.setattr(cli_module, "ensure_deployment_secret", lambda _path: created_secret)
    monkeypatch.setattr(cli_module, "has_administrator", AsyncMock(return_value=has_admin))
    return engine


def _deployment_row(name: str = "Frankfurt") -> SimpleNamespace:
    return SimpleNamespace(id=uuid4(), name=name)


def test_initialize_reports_a_fresh_installation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    row = _deployment_row()
    engine = _patch_initialize(
        monkeypatch,
        deployment=row,
        created_deployment=True,
        created_secret=True,
        has_admin=False,
    )

    assert asyncio.run(cli_module.run_initialize(name="Frankfurt", admin_email=None)) == 0

    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert str(row.id) in output
    assert "identity: generated now" in output
    assert "secret:   generated now" in output


def test_initialize_run_again_generates_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The mode it actually runs in: every restart, every redeploy, every
    # crash loop. A second identity would orphan every enrolled node.
    _patch_initialize(
        monkeypatch,
        deployment=_deployment_row(),
        created_deployment=False,
        created_secret=False,
        has_admin=True,
    )

    assert asyncio.run(cli_module.run_initialize(name="Frankfurt", admin_email=None)) == 0

    output = capsys.readouterr().out
    assert "identity: already existed" in output
    assert "secret:   already existed" in output
    assert "already initialized" in output


def test_initialize_never_invents_an_admin_password(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A generated password has to be printed to be usable, which puts it in
    # container logs and shell history that nobody can clean up afterwards.
    # The command records the address and says what to run instead.
    _patch_initialize(
        monkeypatch,
        deployment=_deployment_row(),
        created_deployment=True,
        created_secret=True,
        has_admin=False,
    )

    asyncio.run(cli_module.run_initialize(name="Frankfurt", admin_email="ops@example.org"))

    output = capsys.readouterr().out
    assert "ops@example.org recorded; no account yet" in output
    assert "seed-admin --email ops@example.org" in output
    assert "password" in output.lower()


def test_initialize_leaves_an_existing_administrator_alone(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Somebody may have changed that password since.
    _patch_initialize(
        monkeypatch,
        deployment=_deployment_row(),
        created_deployment=False,
        created_secret=False,
        has_admin=True,
    )

    asyncio.run(cli_module.run_initialize(name="Frankfurt", admin_email="ops@example.org"))

    output = capsys.readouterr().out
    assert "an administrator account already exists" in output
    assert "seed-admin" not in output


def test_initialize_takes_the_name_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, object] = {}

    async def fake_ensure(_factory: object, *, name: str, admin_email: str | None) -> object:
        captured.update(name=name, admin_email=admin_email)
        return _deployment_row(name), True

    _patch_initialize(
        monkeypatch,
        deployment=_deployment_row(),
        created_deployment=True,
        created_secret=True,
        has_admin=True,
    )
    monkeypatch.setattr(cli_module, "ensure_deployment", fake_ensure)
    monkeypatch.setenv("NEBULA_DEPLOYMENT_NAME", "Helsinki")
    monkeypatch.setenv("NEBULA_ADMIN_EMAIL", "ops@example.org")

    asyncio.run(cli_module.run_initialize(name=None, admin_email=None))

    assert captured == {"name": "Helsinki", "admin_email": "ops@example.org"}


def test_initialize_falls_back_to_a_default_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, object] = {}

    async def fake_ensure(_factory: object, *, name: str, admin_email: str | None) -> object:
        captured["name"] = name
        return _deployment_row(name), True

    _patch_initialize(
        monkeypatch,
        deployment=_deployment_row(),
        created_deployment=True,
        created_secret=True,
        has_admin=True,
    )
    monkeypatch.setattr(cli_module, "ensure_deployment", fake_ensure)
    monkeypatch.delenv("NEBULA_DEPLOYMENT_NAME", raising=False)

    asyncio.run(cli_module.run_initialize(name=None, admin_email=None))

    assert captured["name"] == "Nebula"


def test_main_dispatches_initialize(monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, object] = {}

    async def fake_run(*, name: str | None, admin_email: str | None) -> int:
        received.update(name=name, admin_email=admin_email)
        return 0

    monkeypatch.setattr(cli_module, "run_initialize", fake_run)

    assert main(["initialize", "--name", "Home", "--admin-email", "ops@example.org"]) == 0
    assert received == {"name": "Home", "admin_email": "ops@example.org"}


def _patch_check_database(monkeypatch: pytest.MonkeyPatch, *, current: bool) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    monkeypatch.setattr(
        cli_module, "create_database_engine", lambda _url, **_kwargs: cast(AsyncEngine, engine)
    )
    monkeypatch.setattr(cli_module, "schema_is_current", AsyncMock(return_value=current))
    return engine


def test_check_database_exits_zero_when_ready(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = _patch_check_database(monkeypatch, current=True)

    assert asyncio.run(cli_module.run_check_database()) == 0

    engine.dispose.assert_awaited_once_with()
    assert "Database reachable" in capsys.readouterr().out


def test_check_database_exits_non_zero_when_the_schema_is_behind(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The entrypoint waits on this before initializing. A database that
    # answers but has no tables yet -- migrations still running -- is not
    # ready, and treating it as ready turns a normal startup race into a
    # confusing error about a missing relation.
    _patch_check_database(monkeypatch, current=False)

    assert asyncio.run(cli_module.run_check_database()) == 1
    assert "not reachable" in capsys.readouterr().out


def test_check_database_never_prints_connection_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The database URL carries a password, and this runs in a loop during
    # startup -- so a failure would print it once per second into the logs.
    monkeypatch.setenv("NEBULA_DATABASE_URL", "postgresql+psycopg://u:hunter2@db:5432/nebula")
    _patch_check_database(monkeypatch, current=False)

    asyncio.run(cli_module.run_check_database())

    assert "hunter2" not in capsys.readouterr().out


def test_main_dispatches_check_database(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"ran": False}

    async def fake_run() -> int:
        called["ran"] = True
        return 0

    monkeypatch.setattr(cli_module, "run_check_database", fake_run)

    assert main(["check-database"]) == 0
    assert called["ran"]


def _patch_enrollment(monkeypatch: pytest.MonkeyPatch, service: object) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    monkeypatch.setattr(
        cli_module, "create_database_engine", lambda _url, **_kwargs: cast(AsyncEngine, engine)
    )
    monkeypatch.setattr(
        cli_module, "create_session_factory", lambda _engine: cast(SessionFactory, MagicMock())
    )
    monkeypatch.setattr(cli_module, "load_auth_key_material", lambda _settings: MagicMock())
    monkeypatch.setattr(cli_module, "EnrollmentService", lambda *_a, **_k: service)
    return engine


def test_create_enrollment_token_prints_it_once_with_how_to_revoke(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Printed once because only its digest is stored -- the value cannot be
    # recovered afterwards, which is the point.
    token_id = uuid4()
    service = MagicMock()
    service.mint = AsyncMock(
        return_value=SimpleNamespace(
            token="v1.the-secret-part",  # noqa: S106 - fixture, not a credential
            token_id=token_id,
            label="node-02",
            expires_at=datetime(2026, 9, 12, 12, 0, tzinfo=UTC),
        )
    )
    engine = _patch_enrollment(monkeypatch, service)

    assert asyncio.run(cli_module.run_create_enrollment_token(label="node-02", minutes=30)) == 0

    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert "v1.the-secret-part" in output
    assert "Single use" in output
    assert f"revoke-enrollment-token --id {token_id}" in output


def test_listing_tokens_never_prints_anything_that_could_redeem_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token_id = uuid4()
    service = MagicMock()
    service.outstanding = AsyncMock(
        return_value=[
            SimpleNamespace(
                id=token_id,
                label="node-02",
                expires_at=datetime(2026, 9, 12, 12, 0, tzinfo=UTC),
                token_digest=b"the stored digest",
            )
        ]
    )
    _patch_enrollment(monkeypatch, service)

    asyncio.run(cli_module.run_list_enrollment_tokens())

    output = capsys.readouterr().out
    assert str(token_id) in output
    assert "node-02" in output
    assert "digest" not in output


def test_listing_says_so_when_nothing_is_outstanding(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    service = MagicMock()
    service.outstanding = AsyncMock(return_value=[])
    _patch_enrollment(monkeypatch, service)

    assert asyncio.run(cli_module.run_list_enrollment_tokens()) == 0
    assert "No enrollment tokens are outstanding" in capsys.readouterr().out


def test_revoking_an_outstanding_token_reports_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    service = MagicMock()
    service.revoke = AsyncMock(return_value=True)
    _patch_enrollment(monkeypatch, service)

    assert asyncio.run(cli_module.run_revoke_enrollment_token(token_id=uuid4())) == 0
    assert "can no longer be redeemed" in capsys.readouterr().out


def test_revoking_a_spent_or_unknown_token_exits_non_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Deliberately not distinguishing the two: both mean the token cannot be
    # used, which is what the operator asked for.
    service = MagicMock()
    service.revoke = AsyncMock(return_value=False)
    _patch_enrollment(monkeypatch, service)

    assert asyncio.run(cli_module.run_revoke_enrollment_token(token_id=uuid4())) == 1
    assert "Nothing to revoke" in capsys.readouterr().out


def test_main_dispatches_the_enrollment_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    received: dict[str, object] = {}

    async def fake_create(*, label: str, minutes: int) -> int:
        received.update(label=label, minutes=minutes)
        return 0

    async def fake_revoke(*, token_id: UUID) -> int:
        received["token_id"] = token_id
        return 0

    monkeypatch.setattr(cli_module, "run_create_enrollment_token", fake_create)
    monkeypatch.setattr(cli_module, "run_revoke_enrollment_token", fake_revoke)

    assert main(["create-enrollment-token", "--label", "node-02", "--minutes", "5"]) == 0
    assert received["label"] == "node-02"
    assert received["minutes"] == 5

    identifier = uuid4()
    assert main(["revoke-enrollment-token", "--id", str(identifier)]) == 0
    assert received["token_id"] == identifier


def _patch_reissue_dependencies(
    monkeypatch: pytest.MonkeyPatch, *, result: object
) -> tuple[AsyncMock, AsyncMock]:
    engine = AsyncMock()
    engine.dispose = AsyncMock()
    redis = AsyncMock()
    redis.aclose = AsyncMock()

    monkeypatch.setattr(cli_module, "Settings", lambda: MagicMock())
    monkeypatch.setattr(cli_module, "load_auth_key_material", lambda _settings: MagicMock())
    monkeypatch.setattr(cli_module, "_build_engine", lambda _settings: engine)
    monkeypatch.setattr(cli_module, "create_session_factory", lambda _engine: MagicMock())
    monkeypatch.setattr(cli_module, "RedisAuthState", lambda *a, **k: MagicMock())
    # Patched on the module rather than through it, so mypy is not asked
    # to treat a re-export as part of the CLI's public surface.
    monkeypatch.setattr(redis_asyncio.Redis, "from_url", staticmethod(lambda _url: redis))

    service = MagicMock()
    if isinstance(result, Exception):
        service.reissue_activation = AsyncMock(side_effect=result)
    else:
        service.reissue_activation = AsyncMock(return_value=result)
    monkeypatch.setattr(cli_module, "AccountRequestService", lambda *a, **k: service)
    return engine, redis


def test_reissue_activation_says_when_the_new_link_expires(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    expires_at = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    engine, redis = _patch_reissue_dependencies(monkeypatch, result=expires_at)

    code = asyncio.run(cli_module.run_reissue_activation(email="stranded@example.test"))

    assert code == 0
    output = capsys.readouterr().out
    assert "stranded@example.test" in output
    assert "2026-07-21T12:00:00+00:00" in output
    # Said out loud, because somebody who has just sent a second link will
    # otherwise wonder which of the two the person should use.
    assert "older link no longer works" in output
    engine.dispose.assert_awaited_once_with()
    redis.aclose.assert_awaited_once_with()


def test_reissue_activation_never_prints_the_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # It sets a password, so it is the whole account. A terminal, a shell
    # history and whatever scrollback is being shared are all the wrong
    # places for it.
    _patch_reissue_dependencies(monkeypatch, result=datetime(2026, 7, 21, 12, 0, tzinfo=UTC))

    asyncio.run(cli_module.run_reissue_activation(email="stranded@example.test"))

    captured = capsys.readouterr()
    assert "v1." not in captured.out
    assert "token" not in captured.out.lower()


def test_reissue_activation_reports_a_refusal_and_does_not_succeed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The exit code is what a script branches on; printing the reason and
    # returning zero would let a failed reissue look done.
    engine, redis = _patch_reissue_dependencies(
        monkeypatch, result=ActivationNotReissued("no account exists for nobody@example.test")
    )

    code = asyncio.run(cli_module.run_reissue_activation(email="nobody@example.test"))

    assert code == 1
    assert "no account exists" in capsys.readouterr().err
    # Still cleaned up, even on the refusal path.
    engine.dispose.assert_awaited_once_with()
    redis.aclose.assert_awaited_once_with()


def _patch_prune_dependencies(
    monkeypatch: pytest.MonkeyPatch, summary: PruneSummary, *, migration_url: str | None
) -> tuple[MagicMock, MagicMock, AsyncMock]:
    settings = MagicMock()
    settings.database_url.get_secret_value.return_value = "postgresql+psycopg://app@db/nebula"
    if migration_url is None:
        settings.migration_database_url = None
    else:
        settings.migration_database_url.get_secret_value.return_value = migration_url
    settings.database_connect_timeout_seconds = 3
    settings.database_statement_timeout_ms = 5_000
    monkeypatch.setattr(cli_module, "Settings", lambda: settings)

    engine = MagicMock()
    engine.dispose = AsyncMock()
    create_engine = MagicMock(return_value=engine)
    session_factory = MagicMock()
    prune = AsyncMock(return_value=summary)
    monkeypatch.setattr(cli_module, "create_database_engine", create_engine)
    monkeypatch.setattr(cli_module, "create_session_factory", lambda _engine: session_factory)
    monkeypatch.setattr(cli_module, "prune_history", prune)
    return engine, create_engine, prune


def test_prune_history_uses_the_migration_role_and_reports_counts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = PruneSummary(deleted={"audit_logs": 7, "server_health": 2}, refused={})
    engine, create_engine, prune = _patch_prune_dependencies(
        monkeypatch,
        summary,
        migration_url="postgresql+psycopg://migrator@db/nebula",
    )

    result = asyncio.run(cli_module.run_prune_history(audit_days=365, operational_days=90))

    assert result == 0
    assert create_engine.call_args.args[0] == "postgresql+psycopg://migrator@db/nebula"
    assert prune.await_args is not None
    policy = prune.await_args.args[1]
    assert policy.audit_days == 365
    assert policy.operational_days == 90
    engine.dispose.assert_awaited_once_with()
    assert "Pruned 9 row(s)" in capsys.readouterr().out


def test_prune_history_falls_back_to_the_app_role_and_fails_loudly_on_a_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = PruneSummary(
        deleted={"server_health": 2},
        refused={"audit_logs": "permission denied for table audit_logs"},
    )
    engine, create_engine, _ = _patch_prune_dependencies(monkeypatch, summary, migration_url=None)

    result = asyncio.run(cli_module.run_prune_history(audit_days=365, operational_days=90))

    assert result == 1
    assert create_engine.call_args.args[0] == "postgresql+psycopg://app@db/nebula"
    engine.dispose.assert_awaited_once_with()
    assert "permission denied" in capsys.readouterr().err


def test_main_dispatches_prune_history_with_the_requested_periods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: dict[str, int] = {}

    async def fake_run(*, audit_days: int, operational_days: int) -> int:
        received.update(audit_days=audit_days, operational_days=operational_days)
        return 0

    monkeypatch.setattr(cli_module, "run_prune_history", fake_run)

    assert main(["prune-history", "--audit-days", "400", "--operational-days", "120"]) == 0
    assert received == {"audit_days": 400, "operational_days": 120}


def test_seed_ss2022_command_seeds_the_profile_and_its_adblock_sibling(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    base = SeedProtocolResult(
        status=SeedProtocolStatus.CREATED, protocol_id=uuid4(), protocol_profile_id=uuid4()
    )
    adblock = SeedProtocolResult(
        status=SeedProtocolStatus.CREATED, protocol_id=base.protocol_id, protocol_profile_id=uuid4()
    )
    monkeypatch.setattr(cli_module, "create_database_engine", lambda _url, **_kw: engine)
    monkeypatch.setattr(cli_module, "create_session_factory", lambda _engine: MagicMock())
    monkeypatch.setattr(cli_module, "seed_ss2022_protocol", AsyncMock(return_value=base))
    monkeypatch.setattr(cli_module, "seed_ss2022_adblock_protocol", AsyncMock(return_value=adblock))

    assert asyncio.run(cli_module.run_seed_ss2022_protocol()) == 0

    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert str(base.protocol_profile_id) in output
    assert str(adblock.protocol_profile_id) in output


def test_seed_direct_protocols_command_reports_every_profile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    results = [
        (
            code,
            SeedProtocolResult(
                status=SeedProtocolStatus.CREATED, protocol_id=uuid4(), protocol_profile_id=uuid4()
            ),
        )
        for code in ("vless-enc", "vmess-ws-adblock")
    ]
    monkeypatch.setattr(cli_module, "create_database_engine", lambda _url, **_kw: engine)
    monkeypatch.setattr(cli_module, "create_session_factory", lambda _engine: MagicMock())
    monkeypatch.setattr(cli_module, "seed_direct_protocols", AsyncMock(return_value=results))

    assert asyncio.run(cli_module.run_seed_direct_protocols()) == 0

    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    for _code, result in results:
        assert str(result.protocol_profile_id) in output
