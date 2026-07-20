"""Operator-only commands that never accept secrets through arguments or environment."""

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence
from typing import NoReturn

from sqlalchemy.exc import SQLAlchemyError

from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.seed_admin import SeedAdminStatus, seed_initial_admin
from nebula_api.settings import Settings


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


async def run_seed_admin(*, email: str, username: str | None, password: str) -> int:
    """Run bootstrap using only the application DML credential."""

    settings = Settings()
    engine = create_database_engine(
        settings.database_url.get_secret_value(),
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        statement_timeout_ms=settings.database_statement_timeout_ms,
    )
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


def main(argv: Sequence[str] | None = None) -> int:
    """Parse and execute an operator command."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "seed-admin":
        try:
            password = read_password()
            return asyncio.run(
                run_seed_admin(
                    email=arguments.email,
                    username=arguments.username,
                    password=password,
                )
            )
        except SQLAlchemyError:
            parser.error("database operation failed; no changes were confirmed")
        except (RuntimeError, ValueError) as error:
            parser.error(str(error))
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
