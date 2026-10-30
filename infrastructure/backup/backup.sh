#!/bin/bash
# Daily encrypted backup: a full Postgres dump, /etc/nebula/secrets, the
# installation's generated state (the nebula-state volume: deployment secret,
# node CA, the control plane's agent identity) and the configuration in
# /etc/nebula, archived and age-encrypted to the operator's public key.
#
# Kept in $NEBULA_BACKUP_DIR (default /var/backups/nebula) for
# $NEBULA_BACKUP_KEEP_DAYS days, and also uploaded to Backblaze B2 when
# NEBULA_BACKUP_B2_BUCKET is set. Never decrypts anything; `install.sh
# --restore` does that, with the private key the operator kept.
#
# Run by infrastructure/systemd/nebula-backup.service, itself triggered by
# nebula-backup.timer -- see README.md.
set -euo pipefail

: "${NEBULA_BACKUP_AGE_RECIPIENT:?NEBULA_BACKUP_AGE_RECIPIENT is required}"
: "${POSTGRES_SUPERUSER:?POSTGRES_SUPERUSER is required (from /etc/nebula/compose.env)}"
: "${POSTGRES_SUPERUSER_PASSWORD:?POSTGRES_SUPERUSER_PASSWORD is required (from /etc/nebula/compose.env)}"
POSTGRES_DB="${POSTGRES_DB:?POSTGRES_DB is required (from /etc/nebula/compose.env)}"

COMPOSE_FILE="$(cd "$(dirname "$0")/../compose" && pwd)/production.yaml"
COMPOSE_ENV_FILE="/etc/nebula/compose.env"
SECRETS_DIR="/etc/nebula/secrets"
BACKUP_DIR="${NEBULA_BACKUP_DIR:-/var/backups/nebula}"
KEEP_DAYS="${NEBULA_BACKUP_KEEP_DAYS:-14}"
compose() { docker compose -f "$COMPOSE_FILE" --env-file "$COMPOSE_ENV_FILE" "$@"; }

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

echo "[$timestamp] starting backup"

staging_dir="$work_dir/staging"
mkdir -p "$staging_dir/postgres" "$staging_dir/secrets" "$staging_dir/config"

compose exec -T -e PGPASSWORD="$POSTGRES_SUPERUSER_PASSWORD" postgres \
  pg_dump --username "$POSTGRES_SUPERUSER" --dbname "$POSTGRES_DB" \
  > "$staging_dir/postgres/postgres.sql"

cp -a "$SECRETS_DIR/." "$staging_dir/secrets/"

# Without this a restored server has a new node CA, cannot talk to its own
# agent, and has orphaned every enrolled node (found in a restore drill,
# 2026-10-26). Read through the API's image, which is already on the host.
volume="$(compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["volumes"]["nebula-state"]["name"])')"
api_image="$(compose config --images | grep -m1 -- '-api$' || true)"
docker run --rm --user 0 --entrypoint tar -v "$volume:/state:ro" "${api_image:-nebula-production-api}" \
  -C /state -cf - . > "$staging_dir/state.tar"

# The configuration answers and the agent's settings: the Hysteria2 password
# clients hold is in agent.env, and compose.env holds the database roles the
# dump's grants name.
for f in compose.env agent.env install.conf backup.env; do
  [ -f "/etc/nebula/$f" ] && cp -a "/etc/nebula/$f" "$staging_dir/config/"
done

archive_file="$work_dir/nebula-backup-$timestamp.tar.gz"
tar -czf "$archive_file" -C "$staging_dir" .

encrypted_file="$work_dir/nebula-backup-$timestamp.tar.gz.age"
age --recipient "$NEBULA_BACKUP_AGE_RECIPIENT" --output "$encrypted_file" "$archive_file"

install -d -m 0700 "$BACKUP_DIR"
cp "$encrypted_file" "$BACKUP_DIR/"
find "$BACKUP_DIR" -name 'nebula-backup-*.tar.gz.age' -mtime +"$KEEP_DAYS" -delete

if [ -n "${NEBULA_BACKUP_B2_BUCKET:-}" ]; then
  : "${NEBULA_BACKUP_B2_ENDPOINT:?NEBULA_BACKUP_B2_ENDPOINT is required with a bucket}"
  # Raw-value secret files, since aws-cli only reads these two as env vars.
  AWS_ACCESS_KEY_ID="$(cat "${NEBULA_BACKUP_B2_KEY_ID_FILE:?}")"
  AWS_SECRET_ACCESS_KEY="$(cat "${NEBULA_BACKUP_B2_APPLICATION_KEY_FILE:?}")"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  aws s3 cp "$encrypted_file" "s3://$NEBULA_BACKUP_B2_BUCKET/$(basename "$encrypted_file")" \
    --endpoint-url "$NEBULA_BACKUP_B2_ENDPOINT"
fi

# Recorded only after the backup is stored (set -e stops before this on any
# failure), so the admin security page's "Last backup" is one that exists.
# Not fatal: a missing record shows there as overdue, the safe direction.
compose exec -T -e PGPASSWORD="$POSTGRES_SUPERUSER_PASSWORD" postgres \
  psql --username "$POSTGRES_SUPERUSER" --dbname "$POSTGRES_DB" --quiet -c \
  "insert into audit_logs (id, actor_kind, target_kind, target_id, event_code, outcome, reason_code)
   values (gen_random_uuid(), 'system', 'setting', gen_random_uuid(), 'operation_changed', 'succeeded', 'backup_completed')" \
  || echo "[$timestamp] warning: could not record the backup in the audit log"

echo "[$timestamp] backup complete: $BACKUP_DIR/$(basename "$encrypted_file")${NEBULA_BACKUP_B2_BUCKET:+ and B2}"
