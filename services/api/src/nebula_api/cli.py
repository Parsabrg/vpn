"""Operator-only commands that never accept secrets through arguments or environment."""

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence
from typing import NoReturn

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_api.agent_client.client import AgentClient
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.provisioning.reconciliation import run_reconciliation
from nebula_api.seed_admin import SeedAdminStatus, seed_initial_admin
from nebula_api.settings import Settings
from nebula_api.topology_seed import (
    SeedProtocolStatus,
    create_vpn_server,
    grant_user_server_access,
    seed_wireguard_protocol,
)


class SafeArgumentParser(argparse.ArgumentParser):
    """Avoid reflecting accidentally supplied credential arguments to stderr."""

    def error(self, message: str) -> NoReturn:
        if message.startswith("unrecognized arguments:"):
            message = "unrecognized arguments"
        super().error(message)


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

    print(
        f"Granted user {user_email!r} ({result.user_id}) WireGuard access "
        f"on server {server_code!r}."
    )
    return 0


async def run_reconcile_wireguard() -> int:
    settings = Settings()
    engine = _build_engine(settings)
    try:
        summary = await run_reconciliation(
            create_session_factory(engine),
            lambda agent_host, agent_port: AgentClient(
                agent_host=agent_host, agent_port=agent_port, settings=settings
            ),
            settings,
        )
    finally:
        await engine.dispose()

    print(
        f"Reconciled {summary.checked} peer(s): {summary.in_sync} in sync, "
        f"{summary.repaired} repaired, {summary.repair_failed} repair(s) failed, "
        f"{summary.ambiguous} ambiguous, {summary.errored} errored."
    )
    return 1 if summary.had_problems else 0


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
    except SQLAlchemyError:
        parser.error("database operation failed; no changes were confirmed")
    except (RuntimeError, ValueError) as error:
        parser.error(str(error))
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
