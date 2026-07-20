#!/bin/sh
set -eu

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${NEBULA_DB_APP_USER:?NEBULA_DB_APP_USER is required}"
: "${NEBULA_DB_APP_PASSWORD:?NEBULA_DB_APP_PASSWORD is required}"
: "${NEBULA_DB_MIGRATOR_USER:?NEBULA_DB_MIGRATOR_USER is required}"
: "${NEBULA_DB_MIGRATOR_PASSWORD:?NEBULA_DB_MIGRATOR_PASSWORD is required}"

psql --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
\getenv database POSTGRES_DB
\getenv app_user NEBULA_DB_APP_USER
\getenv app_password NEBULA_DB_APP_PASSWORD
\getenv migrator_user NEBULA_DB_MIGRATOR_USER
\getenv migrator_password NEBULA_DB_MIGRATOR_PASSWORD

CREATE ROLE nebula_app_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE :"migrator_user"
  LOGIN PASSWORD :'migrator_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE :"app_user"
  LOGIN PASSWORD :'app_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT nebula_app_runtime TO :"app_user";

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO :"migrator_user";
GRANT CONNECT ON DATABASE :"database" TO :"migrator_user", nebula_app_runtime;
GRANT USAGE ON SCHEMA public TO nebula_app_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_user" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nebula_app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_user" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO nebula_app_runtime;
SQL
