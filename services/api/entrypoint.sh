#!/bin/sh
# Prepare this installation, then start serving.
#
# Runs on every container start, not just the first one, so everything here
# has to be safe to repeat: a restart, a redeploy and a crash loop all arrive
# at this script in exactly the same way, and it cannot tell them apart.
# `nebula-api initialize` is written for that -- see its docstring for what it
# refuses to do a second time.
#
# What this deliberately does NOT do is migrate. The API connects as a role
# with DML rights and no DDL, which is the point of having two roles: a bug in
# the application cannot alter the schema. Migrations run as the migrator role
# from the `migrate` service, which the compose file makes a completed
# dependency of this one.

set -eu

log() {
    # One prefix, so an operator reading a wall of container output can see
    # which lines are the bootstrap and which are the server.
    echo "[entrypoint] $*"
}

wait_for_database() {
    # The database is a dependency with a healthcheck, so in compose this
    # returns immediately. It matters outside compose -- `docker run` against
    # an external Postgres, a host restarting everything at once, a managed
    # database that takes its time accepting connections -- where the
    # alternative is the container exiting and being restarted in a loop that
    # looks like a crash rather than like waiting.
    attempt=0
    while [ "$attempt" -lt "${NEBULA_DB_WAIT_ATTEMPTS:-60}" ]; do
        if nebula-api check-database >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    log "the database did not become reachable; giving up so this is visible"
    # Non-zero rather than starting anyway: an API that boots without a
    # database answers every request with a 500 and looks like an application
    # fault instead of a missing dependency.
    nebula-api check-database
    return 1
}

if [ "${NEBULA_SKIP_INITIALIZATION:-false}" = "true" ]; then
    # For a deployment that prepares itself some other way, and for anyone
    # debugging a bootstrap they would rather run by hand.
    log "initialization skipped (NEBULA_SKIP_INITIALIZATION=true)"
else
    log "waiting for the database"
    wait_for_database

    log "preparing this installation"
    # Not guarded by a marker file. The command checks the database, which is
    # the only place the answer actually lives -- a file on a volume would
    # claim "already initialized" on a fresh database restored from elsewhere.
    nebula-api initialize
fi

log "starting the API"
exec "$@"
