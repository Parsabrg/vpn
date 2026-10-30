"""Create least-privilege CI roles in an ephemeral PostgreSQL service."""

import os

import psycopg
from psycopg import sql


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def main() -> None:
    admin_url = required_environment("POSTGRES_ADMIN_URL")
    database = required_environment("POSTGRES_DB")
    app_user = required_environment("NEBULA_DB_APP_USER")
    app_password = required_environment("NEBULA_DB_APP_PASSWORD")
    migrator_user = required_environment("NEBULA_DB_MIGRATOR_USER")
    migrator_password = required_environment("NEBULA_DB_MIGRATOR_PASSWORD")

    with psycopg.connect(admin_url, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "CREATE ROLE nebula_app_runtime NOLOGIN NOSUPERUSER "
                "NOCREATEDB NOCREATEROLE NOREPLICATION"
            )
            for role, password in (
                (migrator_user, migrator_password),
                (app_user, app_password),
            ):
                cursor.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN PASSWORD {} "
                        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION"
                    ).format(sql.Identifier(role), sql.Literal(password))
                )
            cursor.execute(
                sql.SQL("GRANT nebula_app_runtime TO {}").format(
                    sql.Identifier(app_user)
                )
            )

            cursor.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            cursor.execute(
                sql.SQL("ALTER SCHEMA public OWNER TO {}").format(
                    sql.Identifier(migrator_user)
                )
            )
            cursor.execute(
                sql.SQL(
                    "GRANT CONNECT ON DATABASE {} TO {}, nebula_app_runtime"
                ).format(
                    sql.Identifier(database),
                    sql.Identifier(migrator_user),
                )
            )
            cursor.execute("GRANT USAGE ON SCHEMA public TO nebula_app_runtime")
            cursor.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES "
                    "TO nebula_app_runtime"
                ).format(sql.Identifier(migrator_user))
            )
            cursor.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                    "GRANT USAGE, SELECT ON SEQUENCES TO nebula_app_runtime"
                ).format(sql.Identifier(migrator_user))
            )


if __name__ == "__main__":
    main()
