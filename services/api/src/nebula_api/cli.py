"""Operator-only commands that never accept secrets through arguments or environment."""

import argparse
import asyncio
import contextlib
import getpass
import os
import secrets
import signal
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import NoReturn, cast
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from redis.asyncio import Redis
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_api.access.expiry import ExpirySummary, enforce_access_expiry
from nebula_api.accounts.email_outbox import EmailOutboxRedisClient
from nebula_api.accounts.service import (
    AccountRequestService,
    ActivationNotReissued,
)
from nebula_api.agent_client.client import AgentClient, AgentClientBuilder
from nebula_api.auth.key_material import AuthKeyMaterial, load_auth_key_material
from nebula_api.auth.redis_state import RedisAuthState, RedisClient
from nebula_api.bootstrap import (
    ensure_control_plane_identity,
    ensure_deployment,
    ensure_deployment_secret,
    ensure_node_authority,
    has_administrator,
)
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.db.schema import SCHEMA_HEAD, schema_is_current
from nebula_api.enrollment.service import EnrollmentService
from nebula_api.provisioning.key_audit import audit_credential_keys
from nebula_api.provisioning.reconciliation import (
    ReconciliationSummary,
    reconciliation_lock,
    run_reconciliation,
    run_xray_orphan_prune,
    run_xray_reconciliation,
)
from nebula_api.provisioning.revocation import credentials_awaiting_removal
from nebula_api.retention import PruneSummary, RetentionPolicy, prune_history
from nebula_api.seed_admin import SeedAdminStatus, seed_initial_admin
from nebula_api.settings import Settings
from nebula_api.topology_seed import (
    EnableCapabilityStatus,
    SeedProtocolResult,
    SeedProtocolStatus,
    create_vpn_server,
    disable_server_capability,
    enable_server_capability,
    grant_user_server_access,
    seed_direct_protocols,
    seed_hysteria2_adblock_protocol,
    seed_hysteria2_protocol,
    seed_ss2022_adblock_protocol,
    seed_ss2022_protocol,
    seed_vless_grpc_adblock_protocol,
    seed_vless_grpc_protocol,
    seed_vless_tcp_adblock_protocol,
    seed_vless_tcp_protocol,
    seed_vless_ws_adblock_protocol,
    seed_vless_ws_protocol,
    seed_vless_xhttp_adblock_protocol,
    seed_vless_xhttp_protocol,
    seed_wireguard_adblock_profile,
    seed_wireguard_protocol,
)
from nebula_api.usage.counters import CounterKeepingAgentClient
from nebula_api.usage.enforcement import EnforcementSummary, enforce_traffic_quotas
from nebula_api.usage.poll import UsagePollSummary, run_usage_poll
from nebula_api.usage.quota import UserNotFound, parse_quota, set_traffic_quota
from nebula_api.usage.service import UsageLedger, UsageService


class SafeArgumentParser(argparse.ArgumentParser):
    """Avoid reflecting accidentally supplied credential arguments to stderr."""

    def error(self, message: str) -> NoReturn:
        if message.startswith("unrecognized arguments:"):
            message = "unrecognized arguments"
        super().error(message)


def _usage_interval(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number of seconds") from None
    # Below this the passes would overlap their own agent calls for no gain.
    if not seconds >= 5:
        raise argparse.ArgumentTypeError("must be at least 5 seconds")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    """Build the intentionally narrow operator command surface."""

    parser = SafeArgumentParser(prog="nebula-api")
    commands = parser.add_subparsers(dest="command", required=True)

    seed = commands.add_parser("seed-admin", help="interactively create the first administrator")
    seed.add_argument("--email", required=True, help="initial administrator email")
    seed.add_argument("--username", help="optional 3-32 character ASCII username")

    commands.add_parser(
        "seed-wireguard-protocol",
        help="create the canonical WireGuard protocol and profile (idempotent, run once)",
    )

    commands.add_parser(
        "seed-vless-xhttp-protocol",
        help="create the canonical VLESS-over-XHTTP+TLS protocol and profile "
        "(idempotent, run once)",
    )

    commands.add_parser(
        "seed-vless-grpc-protocol",
        help="add the VLESS-over-gRPC+TLS profile (idempotent, run once)",
    )

    commands.add_parser(
        "seed-vless-ws-protocol",
        help="add the VLESS-over-WebSocket+TLS profile (idempotent, run once)",
    )

    commands.add_parser(
        "seed-vless-tcp-protocol",
        help="add the VLESS-over-raw-TCP+TLS profile (idempotent, run once)",
    )

    commands.add_parser(
        "seed-hysteria2-protocol",
        help="create the canonical Hysteria2 protocol and profile (idempotent, run once)",
    )

    commands.add_parser(
        "seed-wireguard-adblock-profile",
        help="add the ad-blocking WireGuard sibling profile (idempotent, run once; "
        "requires seed-wireguard-protocol first)",
    )
    commands.add_parser(
        "seed-vless-xhttp-adblock-protocol",
        help="add the ad-blocking VLESS-over-XHTTP+TLS sibling profile (idempotent, run once)",
    )
    commands.add_parser(
        "seed-vless-grpc-adblock-protocol",
        help="add the ad-blocking VLESS-over-gRPC+TLS sibling profile (idempotent, run once)",
    )
    commands.add_parser(
        "seed-vless-ws-adblock-protocol",
        help="add the ad-blocking VLESS-over-WebSocket+TLS sibling profile (idempotent, run once)",
    )
    commands.add_parser(
        "seed-vless-tcp-adblock-protocol",
        help="add the ad-blocking VLESS-over-raw-TCP+TLS sibling profile (idempotent, run once)",
    )
    commands.add_parser(
        "seed-hysteria2-adblock-protocol",
        help="add the ad-blocking Hysteria2 sibling profile (idempotent, run once)",
    )
    commands.add_parser(
        "seed-direct-protocols",
        help="add VLESS Encryption, VMess raw and VMess WebSocket with ad-block siblings "
        "(idempotent)",
    )
    commands.add_parser(
        "seed-ss2022-protocol",
        help="add the Shadowsocks-2022 profile and its ad-blocking sibling (idempotent)",
    )

    enable_capability = commands.add_parser(
        "enable-server-capability",
        help="enable an additional protocol profile on an already-existing VPN server",
    )
    enable_capability.add_argument("--server-code", required=True)
    enable_capability.add_argument(
        "--protocol-profile-code",
        required=True,
        help="e.g. vless-grpc-tls, vless-ws-tls, vless-tcp-tls, hysteria2",
    )

    disable_capability = commands.add_parser(
        "disable-server-capability",
        help="stop offering a protocol profile on a VPN server",
    )
    disable_capability.add_argument("--server-code", required=True)
    disable_capability.add_argument("--protocol-profile-code", required=True)

    create_server = commands.add_parser("create-vpn-server", help="create a VPN server")
    create_server.add_argument("--code", required=True, help="unique server code")
    create_server.add_argument("--display-name", required=True)
    create_server.add_argument("--agent-host", required=True, help="agent mTLS hostname/IP")
    create_server.add_argument("--agent-port", type=int, default=9443)
    create_server.add_argument("--public-host", required=True, help="client-facing hostname/IP")
    create_server.add_argument("--wireguard-client-pool", help="CIDR, e.g. 10.77.0.0/24")
    create_server.add_argument("--wireguard-gateway-address", help="host address inside the pool")
    create_server.add_argument("--maximum-devices", type=int, default=1000)
    create_server.add_argument(
        "--state", choices=["active", "maintenance", "disabled"], default="active"
    )

    grant_access = commands.add_parser(
        "grant-user-access", help="grant a user WireGuard permission and a server assignment"
    )
    grant_access.add_argument("--user-email", required=True)
    grant_access.add_argument("--server-code", required=True)

    commands.add_parser(
        "reconcile-wireguard",
        help="one-shot reconciliation of WireGuard peers against every active agent",
    )

    commands.add_parser(
        "reconcile-xray",
        help="one-shot reconciliation of Xray clients against every active agent",
    )

    collect_usage = commands.add_parser(
        "collect-usage",
        help="poll every active server for traffic counters and accumulate them",
    )
    collect_usage.add_argument(
        "--every",
        type=_usage_interval,
        metavar="SECONDS",
        help="keep running, one pass every SECONDS (at least 5), until stopped",
    )

    retention_defaults = RetentionPolicy()
    prune_history_parser = commands.add_parser(
        "prune-history",
        help="delete operational history older than the retention policy",
    )
    prune_history_parser.add_argument(
        "--audit-days",
        type=int,
        default=retention_defaults.audit_days,
        help=f"keep administrator audit events this long (default {retention_defaults.audit_days})",
    )
    prune_history_parser.add_argument(
        "--operational-days",
        type=int,
        default=retention_defaults.operational_days,
        help=(
            "keep reconciliation, agent-operation, health and email rows this long "
            f"(default {retention_defaults.operational_days})"
        ),
    )

    reissue = commands.add_parser(
        "reissue-activation",
        help="send a fresh activation link to an account that never activated",
    )
    reissue.add_argument("--email", required=True)

    set_quota = commands.add_parser(
        "set-traffic-quota",
        help="set or clear one account's traffic allowance",
    )
    set_quota.add_argument("--email", required=True)
    allowance = set_quota.add_mutually_exclusive_group(required=True)
    # Required and mutually exclusive on purpose. "No allowance given" would
    # otherwise have to mean one of unmetered or zero, and those are
    # opposites.
    allowance.add_argument(
        "--quota",
        help="allowance with a unit, e.g. 100GB, 1.5TB, 500MB (1 GB = 1024 MB)",
    )
    allowance.add_argument(
        "--unmetered",
        action="store_true",
        help="remove the allowance entirely, so the account has no limit",
    )
    enroll_token = commands.add_parser(
        "create-enrollment-token",
        help="mint a single-use token that lets one new VPN node join",
    )
    enroll_token.add_argument("--label", required=True, help="what the new node will be called")
    enroll_token.add_argument(
        "--minutes",
        type=int,
        default=30,
        help="how long the token stays redeemable (default: 30)",
    )

    commands.add_parser(
        "list-enrollment-tokens",
        help="show tokens that could still be redeemed",
    )

    revoke_token = commands.add_parser(
        "revoke-enrollment-token",
        help="withdraw an outstanding enrollment token",
    )
    revoke_token.add_argument("--id", required=True, type=UUID, dest="token_id")

    commands.add_parser(
        "check-database",
        help="exit zero when the database is reachable and its schema is current",
    )

    initialize = commands.add_parser(
        "initialize",
        help="prepare this installation; safe to run on every start",
    )
    initialize.add_argument(
        "--name",
        default=None,
        help="what to call this deployment (default: NEBULA_DEPLOYMENT_NAME, or 'Nebula')",
    )
    initialize.add_argument(
        "--admin-email",
        default=None,
        help="seed this administrator if none exists (default: NEBULA_ADMIN_EMAIL)",
    )

    audit_keys = commands.add_parser(
        "audit-credential-keys",
        help="check every encrypted credential still decrypts, and which key wrote it",
    )
    audit_keys.add_argument(
        "--mark-lost",
        action="store_true",
        help=(
            "record credentials that no held key can open, so a known and "
            "permanent loss stops being re-reported on every read"
        ),
    )

    commands.add_parser(
        "prune-xray-orphans",
        help="remove Xray credentials an agent still serves that no live database row accounts for",
    )

    generate_jwt_key = commands.add_parser(
        "generate-jwt-signing-key",
        help="write a new Ed25519 keypair for JWT signing-key rotation",
    )
    generate_jwt_key.add_argument("--private-key-out", required=True, type=Path)
    generate_jwt_key.add_argument("--public-key-out", required=True, type=Path)

    generate_symmetric_key = commands.add_parser(
        "generate-symmetric-key",
        help="write a new 32-byte token pepper or MFA encryption key for rotation",
    )
    generate_symmetric_key.add_argument(
        "--purpose",
        choices=["token-pepper", "mfa-encryption", "xray-encryption"],
        required=True,
    )
    generate_symmetric_key.add_argument("--out", required=True, type=Path)

    return parser


def read_password() -> str:
    """Read and confirm a password only when a real terminal can hide input."""

    if not sys.stdin.isatty():
        raise RuntimeError("an interactive terminal is required for password entry")
    password = getpass.getpass("Initial administrator password: ")
    confirmation = getpass.getpass("Confirm initial administrator password: ")
    if password != confirmation:
        raise ValueError("password confirmation does not match")
    return password


def _build_engine(settings: Settings) -> AsyncEngine:
    """Every CLI command runs using only the application DML credential."""

    return create_database_engine(
        settings.database_url.get_secret_value(),
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        statement_timeout_ms=settings.database_statement_timeout_ms,
    )


def _print_seed_result(label: str, result: SeedProtocolResult) -> None:
    if result.status is SeedProtocolStatus.ALREADY_SEEDED:
        print(f"{label} already seeded (profile {result.protocol_profile_id}).")
    else:
        print(f"Seeded {label} profile {result.protocol_profile_id}.")


async def run_seed_admin(*, email: str, username: str | None, password: str) -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_initial_admin(
            create_session_factory(engine),
            email=email,
            username=username,
            password=password,
        )
    finally:
        await engine.dispose()

    if result.status is SeedAdminStatus.ALREADY_INITIALIZED:
        print("Administrator store is already initialized; no changes made.")
    else:
        print(f"Created initial administrator {result.admin_id}.")
    return 0


async def run_seed_wireguard_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_wireguard_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()

    if result.status is SeedProtocolStatus.ALREADY_SEEDED:
        print(f"WireGuard protocol already seeded (profile {result.protocol_profile_id}).")
    else:
        print(f"Seeded WireGuard protocol profile {result.protocol_profile_id}.")
    return 0


async def run_seed_vless_xhttp_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_xhttp_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()

    if result.status is SeedProtocolStatus.ALREADY_SEEDED:
        print(
            f"VLESS-over-XHTTP+TLS protocol already seeded (profile {result.protocol_profile_id})."
        )
    else:
        print(f"Seeded VLESS-over-XHTTP+TLS protocol profile {result.protocol_profile_id}.")
    return 0


async def run_seed_vless_grpc_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_grpc_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()

    if result.status is SeedProtocolStatus.ALREADY_SEEDED:
        print(f"VLESS-over-gRPC+TLS profile already seeded (profile {result.protocol_profile_id}).")
    else:
        print(f"Seeded VLESS-over-gRPC+TLS profile {result.protocol_profile_id}.")
    return 0


async def run_seed_vless_ws_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_ws_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()

    if result.status is SeedProtocolStatus.ALREADY_SEEDED:
        print(
            f"VLESS-over-WebSocket+TLS profile already seeded (profile "
            f"{result.protocol_profile_id})."
        )
    else:
        print(f"Seeded VLESS-over-WebSocket+TLS profile {result.protocol_profile_id}.")
    return 0


async def run_seed_vless_tcp_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_tcp_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()

    if result.status is SeedProtocolStatus.ALREADY_SEEDED:
        print(
            f"VLESS-over-raw-TCP+TLS profile already seeded (profile {result.protocol_profile_id})."
        )
    else:
        print(f"Seeded VLESS-over-raw-TCP+TLS profile {result.protocol_profile_id}.")
    return 0


async def run_seed_hysteria2_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_hysteria2_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()

    if result.status is SeedProtocolStatus.ALREADY_SEEDED:
        print(f"Hysteria2 protocol already seeded (profile {result.protocol_profile_id}).")
    else:
        print(f"Seeded Hysteria2 protocol profile {result.protocol_profile_id}.")
    return 0


async def run_seed_wireguard_adblock_profile() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_wireguard_adblock_profile(create_session_factory(engine))
    finally:
        await engine.dispose()
    _print_seed_result("WireGuard (Ad-block)", result)
    return 0


async def run_seed_vless_xhttp_adblock_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_xhttp_adblock_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()
    _print_seed_result("VLESS-over-XHTTP+TLS (Ad-block)", result)
    return 0


async def run_seed_vless_grpc_adblock_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_grpc_adblock_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()
    _print_seed_result("VLESS-over-gRPC+TLS (Ad-block)", result)
    return 0


async def run_seed_vless_ws_adblock_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_ws_adblock_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()
    _print_seed_result("VLESS-over-WebSocket+TLS (Ad-block)", result)
    return 0


async def run_seed_vless_tcp_adblock_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_vless_tcp_adblock_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()
    _print_seed_result("VLESS-over-raw-TCP+TLS (Ad-block)", result)
    return 0


async def run_seed_hysteria2_adblock_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        result = await seed_hysteria2_adblock_protocol(create_session_factory(engine))
    finally:
        await engine.dispose()
    _print_seed_result("Hysteria2 (Ad-block)", result)
    return 0


async def run_seed_direct_protocols() -> int:
    engine = _build_engine(Settings())
    try:
        results = await seed_direct_protocols(create_session_factory(engine))
    finally:
        await engine.dispose()
    for code, result in results:
        _print_seed_result(code, result)
    return 0


async def run_seed_ss2022_protocol() -> int:
    engine = _build_engine(Settings())
    try:
        session_factory = create_session_factory(engine)
        result = await seed_ss2022_protocol(session_factory)
        adblock = await seed_ss2022_adblock_protocol(session_factory)
    finally:
        await engine.dispose()
    _print_seed_result("Shadowsocks-2022", result)
    _print_seed_result("Shadowsocks-2022 (Ad-block)", adblock)
    return 0


async def run_enable_server_capability(*, server_code: str, protocol_profile_code: str) -> int:
    engine = _build_engine(Settings())
    try:
        result = await enable_server_capability(
            create_session_factory(engine),
            server_code=server_code,
            protocol_profile_code=protocol_profile_code,
        )
    finally:
        await engine.dispose()

    if result.status is EnableCapabilityStatus.ALREADY_ENABLED:
        print(f"{protocol_profile_code!r} is already enabled on server {server_code!r}.")
    elif result.status is EnableCapabilityStatus.RE_ENABLED:
        print(f"Re-enabled {protocol_profile_code!r} on server {server_code!r}.")
    else:
        print(f"Enabled {protocol_profile_code!r} on server {server_code!r}.")
    return 0


async def run_disable_server_capability(*, server_code: str, protocol_profile_code: str) -> int:
    engine = _build_engine(Settings())
    try:
        changed = await disable_server_capability(
            create_session_factory(engine),
            server_code=server_code,
            protocol_profile_code=protocol_profile_code,
        )
    finally:
        await engine.dispose()
    print(
        f"Disabled {protocol_profile_code!r} on server {server_code!r}."
        if changed
        else f"{protocol_profile_code!r} was not enabled on server {server_code!r}."
    )
    return 0


async def run_create_vpn_server(
    *,
    code: str,
    display_name: str,
    agent_host: str,
    agent_port: int,
    public_host: str,
    wireguard_client_pool: str | None,
    wireguard_gateway_address: str | None,
    maximum_devices: int,
    state: str,
) -> int:
    engine = _build_engine(Settings())
    try:
        result = await create_vpn_server(
            create_session_factory(engine),
            code=code,
            display_name=display_name,
            agent_host=agent_host,
            agent_port=agent_port,
            public_host=public_host,
            wireguard_client_pool=wireguard_client_pool,
            wireguard_gateway_address=wireguard_gateway_address,
            maximum_devices=maximum_devices,
            state=state,
        )
    finally:
        await engine.dispose()

    print(f"Created VPN server {code!r} ({result.vpn_server_id}) with WireGuard enabled.")
    return 0


async def run_grant_user_access(*, user_email: str, server_code: str) -> int:
    engine = _build_engine(Settings())
    try:
        result = await grant_user_server_access(
            create_session_factory(engine),
            user_email=user_email,
            server_code=server_code,
        )
    finally:
        await engine.dispose()

    count = len(result.profile_codes)
    print(f"Granted user {user_email!r} ({result.user_id}) access to server {server_code!r}.")
    # Named, not counted. An operator checking whether somebody can use
    # Hysteria2 should not have to go to the database to find out.
    print(f"  {count} {'profile' if count == 1 else 'profiles'}: {', '.join(result.profile_codes)}")
    return 0


def _agents_keeping_counters(settings: Settings, engine: AsyncEngine) -> AgentClientBuilder:
    """Agent clients for the sweeps. A repair or a prune is a change like any
    other, so it records the server's traffic counters around itself the way
    the API's own changes do -- see usage/counters.py."""

    ledger = UsageLedger(create_session_factory(engine))

    def build(agent_host: str, agent_port: int) -> AgentClient:
        return CounterKeepingAgentClient(
            agent_host=agent_host, agent_port=agent_port, settings=settings, ledger=ledger
        )

    return build


async def run_reconcile_wireguard() -> int:
    settings = Settings()
    engine = _build_engine(settings)
    try:
        sessions = create_session_factory(engine)
        async with reconciliation_lock(sessions) as acquired:
            if not acquired:
                print("Another reconciliation pass is running; skipped.")
                return 0
            summary = await run_reconciliation(
                sessions, _agents_keeping_counters(settings, engine), settings
            )
    finally:
        await engine.dispose()

    print(
        f"Reconciled {summary.checked} peer(s): {summary.in_sync} in sync, "
        f"{summary.repaired} repaired, {summary.repair_failed} repair(s) failed, "
        f"{summary.ambiguous} ambiguous, {summary.errored} errored."
    )
    return 1 if summary.had_problems else 0


def _format_bytes(count: int) -> str:
    """A figure an operator can check at a glance, beside the exact number."""

    units = (("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024))
    for unit, size in units:
        if count >= size:
            return f"{count / size:.1f} {unit}"
    return f"{count} B"


def _describe_quota(quota_bytes: int | None) -> str:
    if quota_bytes is None:
        return "unmetered (no limit)"
    if quota_bytes == 0:
        # Spelled out, because "0 B" beside "unmetered" is one glance away
        # from being read as the same thing.
        return "0 B -- metered at zero, nothing allowed"
    return f"{_format_bytes(quota_bytes)} ({quota_bytes} bytes)"


async def run_reissue_activation(*, email: str) -> int:
    """Send a fresh activation link, and say nothing about the token.

    The link goes to the address on the account and nowhere else. Printing it
    here would put a credential in a terminal, a shell history and whatever
    scrollback the operator is sharing -- and it is a credential that sets a
    password, so that is the whole account.
    """

    settings = Settings()
    keys = load_auth_key_material(settings)
    engine = _build_engine(settings)
    redis_client = Redis.from_url(settings.redis_url.get_secret_value())
    try:
        service = AccountRequestService(
            create_session_factory(engine),
            RedisAuthState(
                cast(RedisClient, redis_client),
                key_ring=keys.token_peppers,
                current_key_version=settings.token_key_version,
            ),
            cast(EmailOutboxRedisClient, redis_client),
            keys,
            settings,
        )
        try:
            expires_at = await service.reissue_activation(email=email)
        except ActivationNotReissued as error:
            print(f"Not reissued: {error}", file=sys.stderr)
            return 1
    finally:
        await redis_client.aclose()
        await engine.dispose()

    print(f"A new activation link is on its way to {email}.")
    print(f"It expires at {expires_at.isoformat()}, and any older link no longer works.")
    return 0


async def run_set_traffic_quota(*, email: str, quota: str | None, unmetered: bool) -> int:
    quota_bytes = None if unmetered else parse_quota(quota or "")

    settings = Settings()
    # The key ring is needed to report what the account has already used:
    # attributing a counter means decrypting the credentials it belongs to.
    keys = load_auth_key_material(settings)
    engine = _build_engine(settings)
    try:
        service = UsageService(create_session_factory(engine), keys)
        change = await set_traffic_quota(
            create_session_factory(engine),
            service,
            email=email,
            quota_bytes=quota_bytes,
        )
        usage = await service.usage_for_user(change.user_id)
    finally:
        await engine.dispose()

    print(f"Account {change.email}")
    print(f"  was:  {_describe_quota(change.previous_bytes)}")
    print(f"  now:  {_describe_quota(change.quota_bytes)}")
    print(
        f"  used: {_format_bytes(usage.total_bytes)} ({usage.total_bytes} bytes) on this allowance"
    )
    if change.previous_used_bytes:
        # The figure that just went back to zero, so an operator can see what
        # the previous allowance had been spent down to.
        print(f"  the previous allowance had used {_format_bytes(change.previous_used_bytes)}")
    if change.restored_access:
        print("This account was cut off for running out; it can connect again.")
    return 0


def _enrollment_service(settings: Settings, engine: AsyncEngine) -> EnrollmentService:
    keys = load_auth_key_material(settings)
    return EnrollmentService(
        create_session_factory(engine), keys.token_peppers, settings.token_key_version
    )


async def run_create_enrollment_token(*, label: str, minutes: int) -> int:
    settings = Settings()
    engine = _build_engine(settings)
    try:
        minted = await _enrollment_service(settings, engine).mint(
            label=label, lifetime=timedelta(minutes=minutes)
        )
    finally:
        await engine.dispose()

    print(f"Enrollment token for {minted.label}:")
    print()
    # Printed once because it is never stored -- only its digest is, so this
    # value cannot be recovered afterwards. That is the point: a token
    # readable from the database would be a token readable from a backup.
    print(f"  {minted.token}")
    print()
    print(f"Valid until {minted.expires_at.isoformat()}. Single use.")
    print(f"Revoke with: nebula-api revoke-enrollment-token --id {minted.token_id}")
    return 0


async def run_list_enrollment_tokens() -> int:
    settings = Settings()
    engine = _build_engine(settings)
    try:
        outstanding = await _enrollment_service(settings, engine).outstanding()
    finally:
        await engine.dispose()

    if not outstanding:
        print("No enrollment tokens are outstanding.")
        return 0

    print(f"{'id':<38}{'label':<20}expires")
    for token in outstanding:
        # The label and the expiry, never anything that could redeem it.
        print(f"{token.id!s:<38}{token.label:<20}{token.expires_at.isoformat()}")
    return 0


async def run_revoke_enrollment_token(*, token_id: UUID) -> int:
    settings = Settings()
    engine = _build_engine(settings)
    try:
        revoked = await _enrollment_service(settings, engine).revoke(token_id)
    finally:
        await engine.dispose()

    if revoked:
        print("Token revoked; it can no longer be redeemed.")
        return 0
    # Deliberately not distinguishing "unknown" from "already spent": both
    # mean the token cannot be used, which is what the operator asked for.
    print("Nothing to revoke: no such outstanding token.")
    return 1


async def run_check_database() -> int:
    """Whether this process could actually work right now.

    Reachability and schema together, because the entrypoint waits on this
    before initializing and both have to be true for that to succeed. A
    database that answers but has no tables yet -- migrations still running --
    is not ready, and treating it as ready turns a normal startup race into a
    confusing failure about a missing relation.
    """

    settings = Settings()
    engine = _build_engine(settings)
    try:
        current = await schema_is_current(engine)
    finally:
        await engine.dispose()

    if current:
        print(f"Database reachable, schema at {SCHEMA_HEAD}.")
        return 0
    # No connection details, which would carry the password from the URL.
    print(f"Database is not reachable, or its schema is not at {SCHEMA_HEAD}.")
    return 1


async def run_initialize(*, name: str | None, admin_email: str | None) -> int:
    """Prepare this installation, skipping whatever is already done.

    Written to be run on every container start. Each step is checked
    independently, because a bootstrap interrupted halfway is the normal case
    after a first start that failed -- and because re-running must never
    regenerate an identity, replace a secret, or reset an administrator
    somebody has since changed the password of.
    """

    settings = Settings()
    resolved_name = name or os.environ.get("NEBULA_DEPLOYMENT_NAME") or "Nebula"
    resolved_admin = admin_email or os.environ.get("NEBULA_ADMIN_EMAIL")

    engine = _build_engine(settings)
    try:
        session_factory = create_session_factory(engine)
        deployment, created_deployment = await ensure_deployment(
            session_factory, name=resolved_name, admin_email=resolved_admin
        )
        deployment_id = deployment.id
        deployment_name = deployment.name
        created_secret = ensure_deployment_secret(settings.resolved_deployment_secret_file)
        created_authority = ensure_node_authority(
            settings.resolved_node_ca_certificate_file,
            settings.resolved_node_ca_key_file,
            deployment_name=deployment_name,
        )
        # After the authority, and unconditionally: this is what lets the
        # control plane talk to the nodes it enrols, and a deployment that
        # generated a CA but never issued itself a client certificate fails
        # at the first handshake with the agent rather than here.
        created_client = ensure_control_plane_identity(
            settings.resolved_agent_client_cert_file,
            settings.resolved_agent_client_key_file,
            authority_certificate_path=settings.resolved_node_ca_certificate_file,
            authority_key_path=settings.resolved_node_ca_key_file,
        )
        administrator_exists = await has_administrator(session_factory)
    finally:
        await engine.dispose()

    print(f"Deployment: {deployment_name}")
    print(f"  id:       {deployment_id}")
    print(f"  identity: {'generated now' if created_deployment else 'already existed'}")
    print(f"  secret:   {'generated now' if created_secret else 'already existed'}")
    print(f"  node CA:  {'generated now' if created_authority else 'already existed'}")
    print(f"  client:   {'issued now' if created_client else 'already existed'}")

    if administrator_exists:
        print("  admin:    an administrator account already exists")
    elif resolved_admin is not None:
        # Recorded as configuration, but the account still needs a password,
        # and this process will not invent one. A generated password has to be
        # printed to be usable, which puts it in container logs and shell
        # history -- neither of which anybody can clean up afterwards.
        print(f"  admin:    {resolved_admin} recorded; no account yet")
        print()
        print("Create the administrator account with:")
        print(f"  nebula-api seed-admin --email {resolved_admin}")
        print("It prompts for a password, so none is written to a log.")
    else:
        print("  admin:    not configured")
        print()
        print("Set NEBULA_ADMIN_EMAIL, or run `nebula-api seed-admin --email ...`.")

    if not (created_deployment or created_secret or created_authority):
        print()
        print("Nothing to generate; this installation was already initialized.")
    return 0


async def run_audit_credential_keys(*, mark_lost: bool) -> int:
    settings = Settings()
    keys = load_auth_key_material(settings)
    engine = _build_engine(settings)
    try:
        audit = await audit_credential_keys(
            create_session_factory(engine), keys, mark_lost=mark_lost
        )
    finally:
        await engine.dispose()

    print(f"Readable:            {audit.readable}")
    print(f"Unreadable:          {audit.unreadable}")
    print(f"Already marked lost: {audit.already_marked}")
    print(f"No encrypted material: {audit.no_material}")
    if audit.marked_now:
        print(f"Marked lost just now: {audit.marked_now}")

    for version, prints in sorted(audit.fingerprints_by_version.items()):
        print(f"Key version {version} wrote credentials under: {', '.join(sorted(prints))}")

    if audit.versions_with_several_keys:
        # The whole reason the fingerprint is recorded. One version naming two
        # keys means a key file was replaced without the version changing,
        # which is how credentials become permanently unreadable with nothing
        # saying so.
        versions = ", ".join(audit.versions_with_several_keys)
        print(
            f"More than one key has been used under version {versions}. "
            "A key was replaced without its version changing; credentials "
            "written under the earlier key cannot be recovered without it."
        )

    if audit.unreadable and not mark_lost:
        print("Re-run with --mark-lost to record these as unrecoverable.")
    return 1 if audit.unreadable else 0


@dataclass(frozen=True, slots=True)
class _UsagePass:
    summary: UsagePollSummary
    enforcement: EnforcementSummary
    expiry: ExpirySummary
    cut_off: list[ReconciliationSummary]

    @property
    def had_problems(self) -> bool:
        return self.summary.had_problems or any(pass_.had_problems for pass_ in self.cut_off)

    @property
    def changed_anything(self) -> bool:
        return bool(
            self.enforcement.accounts_exhausted or self.expiry.credentials_revoked or self.cut_off
        )


async def _collect_usage_once(
    settings: Settings, keys: AuthKeyMaterial, engine: AsyncEngine
) -> _UsagePass:
    usage = UsageService(create_session_factory(engine), keys)
    summary = await run_usage_poll(
        create_session_factory(engine),
        lambda agent_host, agent_port: AgentClient(
            agent_host=agent_host, agent_port=agent_port, settings=settings
        ),
        usage,
    )
    # Straight after the poll, on the same totals it just wrote. An
    # allowance is only as enforceable as the figures are fresh, and
    # anything between here and the next poll is overshoot nobody can
    # prevent -- see enforcement's module docstring.
    enforcement = await enforce_traffic_quotas(create_session_factory(engine), usage)
    # Access that has lapsed since it was granted -- an expired account,
    # server assignment or protocol permission -- goes the same way.
    expiry = await enforce_access_expiry(create_session_factory(engine))
    cut_off: list[ReconciliationSummary] = []
    if await credentials_awaiting_removal(create_session_factory(engine)):
        # And straight to the servers, whatever marked them: the two
        # passes above, an admin disabling an account or revoking a
        # device. Marking only sets REVOKING; taking a credential off a
        # server is reconciliation's job, and waiting for the sweep's own
        # timer left an account that had spent its allowance connected for
        # another sixteen minutes -- measured.
        agents = _agents_keeping_counters(settings, engine)
        cut_off.append(await run_reconciliation(create_session_factory(engine), agents, settings))
        cut_off.append(
            await run_xray_reconciliation(create_session_factory(engine), agents, settings, keys)
        )
    return _UsagePass(summary, enforcement, expiry, cut_off)


def _report_usage_pass(outcome: _UsagePass) -> None:
    summary, enforcement, expiry, cut_off = (
        outcome.summary,
        outcome.enforcement,
        outcome.expiry,
        outcome.cut_off,
    )
    print(
        f"Polled {summary.servers_polled} server(s), {summary.servers_failed} unreachable: "
        f"{summary.samples} sample(s), {summary.credentials_active} credential(s) active."
    )
    if enforcement.accounts_exhausted:
        print(
            f"Revoked {enforcement.credentials_revoked} credential(s) across "
            f"{enforcement.accounts_exhausted} account(s) that spent their allowance."
        )
    if expiry.credentials_revoked:
        print(
            f"Ended lapsed access: {expiry.credentials_revoked} credential(s) across "
            f"{len(expiry.account_ids)} account(s)."
        )
    if cut_off:
        removed = sum(pass_.repaired for pass_ in cut_off)
        failed = sum(pass_.repair_failed + pass_.errored for pass_ in cut_off)
        print(f"Taken off the servers now: {removed} credential(s), {failed} failed.")
    if enforcement.already_enforced:
        print(f"Still cut off: {enforcement.already_enforced} account(s).")
    if summary.sources_failed:
        print(f"Sources that could not be read: {', '.join(summary.sources_failed)}")


async def run_collect_usage() -> int:
    settings = Settings()
    # Needs the key ring for the same reason the Xray sweep does: attributing
    # a counter to an account means resolving credentials that only exist
    # encrypted at rest.
    keys = load_auth_key_material(settings)
    engine = _build_engine(settings)
    try:
        outcome = await _collect_usage_once(settings, keys, engine)
    finally:
        await engine.dispose()

    _report_usage_pass(outcome)
    return 1 if outcome.had_problems else 0


# Touched after every pass that finished, so the container's health check can
# tell a loop that is working from one that is stuck or failing every time.
USAGE_HEARTBEAT = Path(tempfile.gettempdir()) / "nebula-usage-pass"

# A pass is one call per server and a few queries. One that takes this long is
# hung on something, and holding every later pass back behind it would undo
# the point of running often.
USAGE_PASS_BUDGET_SECONDS = 50.0

# How often a quiet loop says it is still running.
USAGE_REPORT_SECONDS = 3600.0


def _stop_on_signals(loop: asyncio.AbstractEventLoop) -> asyncio.Event:
    """An event set by SIGTERM or SIGINT: `docker stop`, or Ctrl-C by hand."""

    stop = asyncio.Event()
    for signal_number in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signal_number, stop.set)
    return stop


async def run_collect_usage_every(seconds: float, *, stop: asyncio.Event | None = None) -> int:
    """Collect usage and enforce allowances every [seconds], until stopped.

    How often this runs is how far past its allowance an account gets: the
    one-minute timer let a phone on a 30 MB allowance reach 76 MB at 1 MB/s.
    Starting Python, loading the key ring and connecting to the database
    every few seconds would cost more than the pass itself, so this keeps
    all three and runs as its own container (the `usage` service).

    Quiet while nothing happens: a line per pass would be thousands a day. It
    prints what a pass changed or failed at, and once an hour how many
    passes ran.
    """

    settings = Settings()
    keys = load_auth_key_material(settings)
    engine = _build_engine(settings)
    loop = asyncio.get_running_loop()
    if stop is None:
        stop = _stop_on_signals(loop)
    passes_per_report = max(1, round(USAGE_REPORT_SECONDS / seconds))
    passes = failures = 0
    print(f"Collecting usage every {seconds:g} seconds.")
    try:
        while not stop.is_set():
            started = loop.time()
            try:
                async with asyncio.timeout(USAGE_PASS_BUDGET_SECONDS):
                    outcome = await _collect_usage_once(settings, keys, engine)
            except TimeoutError:
                failures += 1
                print(f"A usage pass took over {USAGE_PASS_BUDGET_SECONDS:g}s and was abandoned.")
            # Whatever one pass runs into, the next one runs regardless.
            except Exception as error:
                failures += 1
                # The type only: a driver's message can carry a connection
                # string.
                print(f"A usage pass failed: {type(error).__name__}.")
            else:
                await asyncio.to_thread(USAGE_HEARTBEAT.touch)
                if outcome.changed_anything or outcome.had_problems:
                    _report_usage_pass(outcome)
            passes += 1
            if passes % passes_per_report == 0:
                print(f"Collected usage {passes_per_report} time(s), {failures} failed.")
                failures = 0
            remaining = seconds - (loop.time() - started)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=max(remaining, 0.0))
    finally:
        await engine.dispose()
    return 0


async def run_reconcile_xray() -> int:
    settings = Settings()
    # Unlike the WireGuard pass, this one needs the key ring: an Xray client is
    # addressed by a UUID that only exists encrypted at rest, so it cannot even
    # be asked about without decrypting its credential first.
    keys = load_auth_key_material(settings)
    engine = _build_engine(settings)
    try:
        sessions = create_session_factory(engine)
        async with reconciliation_lock(sessions) as acquired:
            if not acquired:
                print("Another reconciliation pass is running; skipped.")
                return 0
            summary = await run_xray_reconciliation(
                sessions, _agents_keeping_counters(settings, engine), settings, keys
            )
    finally:
        await engine.dispose()

    print(
        f"Reconciled {summary.checked} xray client(s): {summary.in_sync} in sync, "
        f"{summary.repaired} repaired, {summary.repair_failed} repair(s) failed, "
        f"{summary.ambiguous} ambiguous, {summary.errored} errored."
    )
    return 1 if summary.had_problems else 0


def _report_prune_summary(summary: PruneSummary) -> None:
    counts = ", ".join(f"{table}={count}" for table, count in summary.deleted.items())
    print(f"Pruned {summary.total_deleted} row(s) of history ({counts or 'nothing to delete'}).")
    for table, reason in summary.refused.items():
        print(f"Could not prune {table}: {reason}", file=sys.stderr)


async def run_prune_history(*, audit_days: int, operational_days: int) -> int:
    settings = Settings()
    # Production supplies the migration role to this one-shot command because
    # audit_logs is deliberately append-only to the application's ordinary
    # role. Falling back keeps the command useful in development and makes a
    # missing migration credential explicit in its summary and exit status:
    # PostgreSQL refuses the audit delete while the other tables are pruned.
    credential = settings.migration_database_url or settings.database_url
    engine = create_database_engine(
        credential.get_secret_value(),
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        statement_timeout_ms=settings.database_statement_timeout_ms,
    )
    try:
        summary = await prune_history(
            create_session_factory(engine),
            RetentionPolicy(audit_days=audit_days, operational_days=operational_days),
        )
    finally:
        await engine.dispose()

    _report_prune_summary(summary)
    return 1 if summary.refused else 0


async def run_prune_xray_orphans() -> int:
    settings = Settings()
    keys = load_auth_key_material(settings)
    engine = _build_engine(settings)
    try:
        summary = await run_xray_orphan_prune(
            create_session_factory(engine),
            _agents_keeping_counters(settings, engine),
            keys,
        )
    finally:
        await engine.dispose()

    print(
        f"Pruned {summary.servers} server(s): {summary.removed} untracked credential(s) removed, "
        f"{summary.kept} kept, {summary.skipped} server(s) skipped, {summary.errored} errored."
    )
    return 1 if summary.had_problems else 0


async def run_generate_jwt_signing_key(*, private_key_out: Path, public_key_out: Path) -> int:
    """Generate a fresh Ed25519 keypair for JWT rotation; never overwrites an existing file.

    Deploying it (new `NEBULA_JWT_KEY_ID`, retiring the old public key into
    `NEBULA_JWT_PREVIOUS_PUBLIC_KEYS_DIR`) is an operator step -- see docs/environment.md.
    """

    signer = Ed25519PrivateKey.generate()
    private_bytes = signer.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = signer.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_new_secret_file(private_key_out, private_bytes)
    _write_new_secret_file(public_key_out, public_bytes)
    print(f"Wrote a new Ed25519 keypair to {private_key_out} and {public_key_out}.")
    return 0


async def run_generate_symmetric_key(*, purpose: str, out: Path) -> int:
    """Generate a fresh 32-byte pepper/MFA key for rotation; never overwrites an existing file."""

    _write_new_secret_file(out, secrets.token_bytes(32))
    print(f"Wrote a new {purpose} key to {out}.")
    return 0


def _write_new_secret_file(path: Path, data: bytes) -> None:
    """Create `path` exclusively (never overwrite) with best-effort owner-only permissions."""

    try:
        with path.open("xb") as handle:
            handle.write(data)
    except OSError as error:
        raise ValueError(f"cannot write {path}: {error.strerror or error}") from None
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main(argv: Sequence[str] | None = None) -> int:
    """Parse and execute an operator command."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "seed-admin":
            password = read_password()
            return asyncio.run(
                run_seed_admin(
                    email=arguments.email,
                    username=arguments.username,
                    password=password,
                )
            )
        if arguments.command == "seed-wireguard-protocol":
            return asyncio.run(run_seed_wireguard_protocol())
        if arguments.command == "seed-vless-xhttp-protocol":
            return asyncio.run(run_seed_vless_xhttp_protocol())
        if arguments.command == "seed-vless-grpc-protocol":
            return asyncio.run(run_seed_vless_grpc_protocol())
        if arguments.command == "seed-vless-ws-protocol":
            return asyncio.run(run_seed_vless_ws_protocol())
        if arguments.command == "seed-vless-tcp-protocol":
            return asyncio.run(run_seed_vless_tcp_protocol())
        if arguments.command == "seed-hysteria2-protocol":
            return asyncio.run(run_seed_hysteria2_protocol())
        if arguments.command == "seed-wireguard-adblock-profile":
            return asyncio.run(run_seed_wireguard_adblock_profile())
        if arguments.command == "seed-vless-xhttp-adblock-protocol":
            return asyncio.run(run_seed_vless_xhttp_adblock_protocol())
        if arguments.command == "seed-vless-grpc-adblock-protocol":
            return asyncio.run(run_seed_vless_grpc_adblock_protocol())
        if arguments.command == "seed-vless-ws-adblock-protocol":
            return asyncio.run(run_seed_vless_ws_adblock_protocol())
        if arguments.command == "seed-vless-tcp-adblock-protocol":
            return asyncio.run(run_seed_vless_tcp_adblock_protocol())
        if arguments.command == "seed-hysteria2-adblock-protocol":
            return asyncio.run(run_seed_hysteria2_adblock_protocol())
        if arguments.command == "seed-direct-protocols":
            return asyncio.run(run_seed_direct_protocols())
        if arguments.command == "seed-ss2022-protocol":
            return asyncio.run(run_seed_ss2022_protocol())
        if arguments.command == "enable-server-capability":
            return asyncio.run(
                run_enable_server_capability(
                    server_code=arguments.server_code,
                    protocol_profile_code=arguments.protocol_profile_code,
                )
            )
        if arguments.command == "disable-server-capability":
            return asyncio.run(
                run_disable_server_capability(
                    server_code=arguments.server_code,
                    protocol_profile_code=arguments.protocol_profile_code,
                )
            )
        if arguments.command == "create-vpn-server":
            return asyncio.run(
                run_create_vpn_server(
                    code=arguments.code,
                    display_name=arguments.display_name,
                    agent_host=arguments.agent_host,
                    agent_port=arguments.agent_port,
                    public_host=arguments.public_host,
                    wireguard_client_pool=arguments.wireguard_client_pool,
                    wireguard_gateway_address=arguments.wireguard_gateway_address,
                    maximum_devices=arguments.maximum_devices,
                    state=arguments.state,
                )
            )
        if arguments.command == "grant-user-access":
            return asyncio.run(
                run_grant_user_access(
                    user_email=arguments.user_email,
                    server_code=arguments.server_code,
                )
            )
        if arguments.command == "reconcile-wireguard":
            return asyncio.run(run_reconcile_wireguard())
        if arguments.command == "reconcile-xray":
            return asyncio.run(run_reconcile_xray())
        if arguments.command == "create-enrollment-token":
            return asyncio.run(
                run_create_enrollment_token(label=arguments.label, minutes=arguments.minutes)
            )
        if arguments.command == "list-enrollment-tokens":
            return asyncio.run(run_list_enrollment_tokens())
        if arguments.command == "revoke-enrollment-token":
            return asyncio.run(run_revoke_enrollment_token(token_id=arguments.token_id))
        if arguments.command == "check-database":
            return asyncio.run(run_check_database())
        if arguments.command == "initialize":
            return asyncio.run(
                run_initialize(
                    name=arguments.name,
                    admin_email=arguments.admin_email,
                )
            )
        if arguments.command == "audit-credential-keys":
            return asyncio.run(run_audit_credential_keys(mark_lost=arguments.mark_lost))
        if arguments.command == "collect-usage":
            if arguments.every is not None:
                return asyncio.run(run_collect_usage_every(arguments.every))
            return asyncio.run(run_collect_usage())
        if arguments.command == "reissue-activation":
            return asyncio.run(run_reissue_activation(email=arguments.email))
        if arguments.command == "set-traffic-quota":
            return asyncio.run(
                run_set_traffic_quota(
                    email=arguments.email,
                    quota=arguments.quota,
                    unmetered=arguments.unmetered,
                )
            )
        if arguments.command == "prune-history":
            return asyncio.run(
                run_prune_history(
                    audit_days=arguments.audit_days,
                    operational_days=arguments.operational_days,
                )
            )
        if arguments.command == "prune-xray-orphans":
            return asyncio.run(run_prune_xray_orphans())
        if arguments.command == "generate-jwt-signing-key":
            return asyncio.run(
                run_generate_jwt_signing_key(
                    private_key_out=arguments.private_key_out,
                    public_key_out=arguments.public_key_out,
                )
            )
        if arguments.command == "generate-symmetric-key":
            return asyncio.run(
                run_generate_symmetric_key(purpose=arguments.purpose, out=arguments.out)
            )
    except UserNotFound as missing:
        # Named rather than folded into the generic handler: "no account with
        # that address" is almost always a typo the operator can fix, and is
        # worth distinguishing from a command that failed for another reason.
        parser.error(f"no account with the address {missing.args[0]!r}")
    except SQLAlchemyError:
        parser.error("database operation failed; no changes were confirmed")
    except (RuntimeError, ValueError) as error:
        parser.error(str(error))
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
