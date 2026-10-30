#!/usr/bin/env bash
# Nebula VPN server installer.
#
#   git clone <repository> nebula && cd nebula && sudo ./install.sh
#
# Takes a fresh Ubuntu/Debian server to a working Nebula: control plane, admin
# panel, VPN agent, Xray, Hysteria2 and WireGuard, with a certificate. It asks
# only for what it cannot decide: the domain, the administrator, and how email
# is sent. Safe to run again: anything already done is kept (secrets are never
# regenerated), so a rerun is also how to resume after a failure or update.
#
# Every prompt can be answered ahead of time for unattended runs:
#   NEBULA_DOMAIN, NEBULA_ADMIN_EMAIL, NEBULA_EMAIL_MODE (smtp|resend|skip),
#   NEBULA_SMTP_HOST, NEBULA_SMTP_PORT, NEBULA_SMTP_USERNAME, NEBULA_SMTP_PASSWORD,
#   NEBULA_RESEND_API_KEY, NEBULA_EMAIL_FROM, NEBULA_INSTALL_PROXY, NEBULA_ASSUME_YES=1
#
# Rebuilding a lost server from a backup, on a fresh one:
#   sudo ./install.sh --restore nebula-backup-<time>.tar.gz.age
# It asks for the backup key (or reads NEBULA_BACKUP_KEY_FILE) and nothing else.
#
# Updating to the newest release (a v* tag; or name one), then a rerun:
#   sudo ./install.sh --update [v0.1.34]
#
# Changing which protocols this server offers, or their ports (firewall,
# nginx, WireGuard and the control plane follow):
#   sudo ./install.sh --configure
#
# Adding a second VPN server to an existing Nebula (the admin panel's "Add
# server" gives the token):
#   sudo ./install.sh --join https://api.example.com:8444 --token v1....
# Only the VPN half is installed there; users, the panel and backups stay on
# the first server, which this one enrols with.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ETC=/etc/nebula
SECRETS=$ETC/secrets
STATE=$ETC/install.conf
COMPOSE_FILE=$REPO/infrastructure/compose/production.yaml
PROJECT=nebula-production
XRAY_VERSION=26.9.30
HYSTERIA_VERSION=2.9.2
# From the publishers' own .dgst / hashes.txt; Xray checked 2026-10-30,
# Hysteria2 2026-10-26.
declare -A XRAY_SHA=(
  [amd64]=f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e
  [arm64]=9886f077f9fd8e6713b84c377c1c7db4e53b9bfa8c276a5bd12561139522b473
)
declare -A HYSTERIA_SHA=(
  [amd64]=86fef8e2f1b2bf41318ac96724eee6c3b449e4e510022cc89658b63a6713922a
  [arm64]=9ec8f49f4ea554b1cac04e6f3690cea76ff835082e943e54196d7f323fcfba71
)

bold=$'\e[1m'; green=$'\e[32m'; yellow=$'\e[33m'; red=$'\e[31m'; reset=$'\e[0m'
step() { printf '\n%s==> %s%s\n' "$bold" "$*" "$reset"; }
ok() { printf '%s  ok%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '%s  warning:%s %s\n' "$yellow" "$reset" "$*"; }
die() { printf '%serror:%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }

# ask VAR "Prompt" [default] [secret]: keeps a value already set (environment
# or a previous run), otherwise prompts.
ask() {
  local var=$1 prompt=$2 default=${3:-} secret=${4:-} answer
  [ -n "${!var:-}" ] && return
  [ -t 0 ] || die "$var is not set and there is no terminal to ask on"
  while :; do
    if [ -n "$secret" ]; then
      read -rsp "$prompt: " answer; echo
    else
      read -rp "$prompt${default:+ [$default]}: " answer
    fi
    answer=${answer:-$default}
    [ -n "$answer" ] && break
    echo "  (required)"
  done
  printf -v "$var" '%s' "$answer"
}

confirm() {
  [ "${NEBULA_ASSUME_YES:-}" = 1 ] && return 0
  [ -t 0 ] || return 0
  local answer; read -rp "$1 [Y/n]: " answer
  [[ ! $answer =~ ^[Nn] ]]
}

remember() {
  touch "$STATE"; chmod 0600 "$STATE"
  sed -i "/^$1=/d" "$STATE"; printf '%s=%q\n' "$1" "$2" >> "$STATE"
}

compose() { docker compose -p "$PROJECT" --env-file "$ETC/compose.env" -f "$COMPOSE_FILE" "$@"; }

# Adds WireGuard's NAT and client restrictions to a ufw before.rules file,
# once (marked), leaving everything else in it as it was. $1 is the outgoing
# interface, $2 the file.
WG_BLOCKED="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"
wireguard_routing() {
  local wan=$1 file=$2 nat forward n
  grep -q 'nebula-wireguard' "$file" && return 0
  nat="# nebula-wireguard: clients' traffic leaves as this host\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s $WG_POOL -o $wan -j MASQUERADE\nCOMMIT\n"
  forward="# nebula-wireguard: not each other, not this host's networks\n-A ufw-before-forward -i wg0 -o wg0 -j REJECT\n"
  for n in $WG_BLOCKED; do forward+="-A ufw-before-forward -i wg0 -d $n -j REJECT\n"; done
  forward+="-A ufw-before-input -i wg0 -j REJECT\n"
  awk -v nat="$nat" -v fwd="$forward" '
    NR == 1 { printf "%s", nat }
    /^-A ufw-before-input -i lo -j ACCEPT/ && !done { printf "%s", fwd; done = 1 }
    { print }' "$file" > "$file.nebula" && cat "$file.nebula" > "$file" && rm -f "$file.nebula"
}
api() { compose exec -T api nebula-api "$@"; }

# Downloads that fail from some networks (PyPI's file host and GitHub are slow
# or blocked from Iran) go through NEBULA_INSTALL_PROXY when one is given.
fetch() { curl -fsSL --retry 3 -m 600 ${NEBULA_INSTALL_PROXY:+--proxy "$NEBULA_INSTALL_PROXY"} "$@"; }

[ "$(id -u)" = 0 ] || die "run as root: sudo ./install.sh"
# Two runs at once recreate the same containers and collide, leaving them
# stopped (seen 2026-10-29). The lock is released when this process exits.
exec 9>/run/nebula-install.lock
flock -n 9 || die "another ./install.sh is already running; wait for it to finish"
command -v apt-get >/dev/null || die "this installer supports Ubuntu and Debian"
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU architecture $(uname -m)" ;;
esac
if [ "${1:-}" = --update ]; then
  # A release, not whatever main holds: the newest v* tag, or the one given.
  # Shows what changed, then installs from it as a rerun would.
  g() { git -c safe.directory="$REPO" -C "$REPO" "$@"; }
  g rev-parse --git-dir >/dev/null 2>&1 || die "$REPO is not a git checkout: copy the release here, then run sudo ./install.sh"
  [ -z "$(g status --porcelain --untracked-files=no)" ] || die "$REPO has local changes (git status); undo or commit them first"
  HTTPS_PROXY=${NEBULA_INSTALL_PROXY:-} g fetch -q --tags origin || die "could not fetch the releases"
  tag=${2:-$(g tag -l 'v*' --sort=-v:refname | awk 'NR == 1')}
  g rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "there is no release ${tag:-at all}"
  # Never backwards: older code than the database's migrations would not start.
  g merge-base --is-ancestor HEAD "refs/tags/$tag" \
    || die "$tag is not newer than this checkout ($(g describe --tags --always)); wait for the next release"
  step "Updating $(g describe --tags --always) to $tag"
  g log --oneline --no-decorate HEAD.."refs/tags/$tag" | awk 'NR <= 40'
  echo "Release notes: $REPO/CHANGELOG.md"
  g -c advice.detachedHead=false checkout -q "refs/tags/$tag"
  exec "$REPO/install.sh"
fi
RESTORE_DIR=""
if [ "${1:-}" = --restore ]; then
  backup=${2:?usage: sudo ./install.sh --restore <backup file>}
  [ -f "$backup" ] || die "no backup at $backup"
  [ -f $ETC/compose.env ] && die "this server already has an installation; restore onto a fresh one"
  step "Unpacking the backup"
  apt-get -qq update && apt-get -qq install -y age >/dev/null
  key=${NEBULA_BACKUP_KEY_FILE:-}
  if [ -z "$key" ]; then
    [ -t 0 ] || die "set NEBULA_BACKUP_KEY_FILE to the backup key file"
    read -rsp "Backup key (the AGE-SECRET-KEY-... line you saved): " secret; echo
    key=$(mktemp); printf '%s\n' "$secret" > "$key"; unset secret
  fi
  RESTORE_DIR=$(mktemp -d /root/nebula-restore.XXXXXX)
  age --decrypt -i "$key" "$backup" | tar -xzf - -C "$RESTORE_DIR" || die "that key does not open this backup"
  install -d -m 0755 $ETC
  cp -a "$RESTORE_DIR/config/." $ETC/
  # Not kept on the server: encrypting needs only the public half, which
  # backup.env already names. A copy here would open every backup.
  [ -z "${NEBULA_BACKUP_KEY_FILE:-}" ] && rm -f "$key"
  getent group nebula-secrets >/dev/null || groupadd --gid 9443 nebula-secrets
  install -d -o root -g nebula-secrets -m 0750 $SECRETS
  cp -a "$RESTORE_DIR/secrets/." $SECRETS/
  ok "configuration and keys restored; the database follows once it is running"
fi

CONFIGURE=""
[ "${1:-}" = --configure ] && CONFIGURE=1
JOIN_URL="" JOIN_TOKEN=""
if [ "${1:-}" = --join ]; then
  JOIN_URL=${2:-}; [ "${3:-}" = --token ] && JOIN_TOKEN=${4:-}
  [[ $JOIN_URL == https://* ]] && [ -n "$JOIN_TOKEN" ] \
    || die "usage: sudo ./install.sh --join https://<your API address> --token <token from Add server>"
  JOIN_URL=${JOIN_URL%/}
fi

install -d -m 0755 $ETC
# Saved answers fill in only what the environment did not give.
GIVEN_EMAIL_MODE=${NEBULA_EMAIL_MODE:-}
if [ -f "$STATE" ]; then
  while IFS= read -r line; do
    name=${line%%=*}
    [[ $name =~ ^NEBULA_[A-Z_]+$ ]] && [ -z "${!name:-}" ] && eval "$line"
  done < "$STATE"
fi

# A rerun on a server that joined stays a joined server.
JOIN_URL=${JOIN_URL:-${NEBULA_JOIN_URL:-}}
[ -n "$JOIN_URL" ] && remember NEBULA_JOIN_URL "$JOIN_URL"

cat <<EOF
${bold}Nebula VPN installer${reset}${JOIN_URL:+ (adding a server to $JOIN_URL)}
Installs into $REPO. Answers are saved in $STATE, so a rerun asks nothing twice.
EOF

# --- Questions first, so the rest runs unattended --------------------------

step "Server address"
PUBLIC_IP=$(curl -4 -fsS -m 10 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' || true)
[ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(curl -4 -fsS -m 10 https://ifconfig.me 2>/dev/null || true)
[ -n "$PUBLIC_IP" ] || die "could not find this server's public IPv4 address"
echo "This server's public address is $PUBLIC_IP."
if [ -n "$JOIN_URL" ]; then
  echo "This server needs a name of its own that clients connect to, e.g. vpn2.example.com."
else
  echo "Nebula needs a domain name you control, e.g. vpn.example.com. It serves:"
  echo "  panel.<domain>  the admin panel"
  echo "  api.<domain>    the API the apps talk to"
  echo "  <domain>        the VPN itself"
fi
ask NEBULA_DOMAIN "Domain for this server (e.g. vpn.example.com)"
NEBULA_DOMAIN=${NEBULA_DOMAIN,,}; NEBULA_DOMAIN=${NEBULA_DOMAIN%.}
[[ $NEBULA_DOMAIN =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]] || die "'$NEBULA_DOMAIN' is not a domain name"
remember NEBULA_DOMAIN "$NEBULA_DOMAIN"
PANEL=panel.$NEBULA_DOMAIN; APIHOST=api.$NEBULA_DOMAIN
# A joined server has one name, and its certificate only that one.
if [ -n "$JOIN_URL" ]; then CERTNAME=$NEBULA_DOMAIN; NAMES=("$NEBULA_DOMAIN"); else
  CERTNAME=$PANEL; NAMES=("$NEBULA_DOMAIN" "$PANEL" "$APIHOST"); fi
CERT=/etc/letsencrypt/live/$CERTNAME

step "Administrator"
ask NEBULA_ADMIN_EMAIL "Admin email$([ -n "$JOIN_URL" ] && echo " (for certificate expiry notices)")"
[[ $NEBULA_ADMIN_EMAIL == *@*.* ]] || die "'$NEBULA_ADMIN_EMAIL' is not an email address"
remember NEBULA_ADMIN_EMAIL "$NEBULA_ADMIN_EMAIL"

if [ -z "$JOIN_URL" ]; then
step "Email delivery"
# A choice saved by an earlier run is shown and can be changed, so a rerun is
# how to add or fix email; a skip is asked again outright.
if [ -n "${NEBULA_EMAIL_MODE:-}" ] && [ "$NEBULA_EMAIL_MODE" != skip ] && [ -z "$GIVEN_EMAIL_MODE" ] && [ -t 0 ]; then
  echo "Email is sent with $NEBULA_EMAIL_MODE, from $NEBULA_EMAIL_FROM."
  read -rp "Change it? [y/N]: " change
  if [[ $change =~ ^[Yy] ]]; then
    unset NEBULA_EMAIL_MODE NEBULA_EMAIL_FROM NEBULA_SMTP_HOST NEBULA_SMTP_PORT NEBULA_SMTP_USERNAME
    rm -f $SECRETS/smtp_password $SECRETS/resend_api_key
  fi
fi
if [ -z "${NEBULA_EMAIL_MODE:-}" ] || { [ "$NEBULA_EMAIL_MODE" = skip ] && [ -z "$GIVEN_EMAIL_MODE" ] && [ -t 0 ]; }; then
  echo "Nebula emails people their activation and password-reset links."
  echo "  1) SMTP server (Gmail, Zoho, your host's mail server, ...)"
  echo "  2) Resend (resend.com API key)"
  echo "  3) Skip for now (no emails until you rerun this installer)"
  unset NEBULA_EMAIL_MODE
  ask NEBULA_EMAIL_MODE "Choose 1, 2 or 3" 3
  case $NEBULA_EMAIL_MODE in 1|smtp) NEBULA_EMAIL_MODE=smtp ;; 2|resend) NEBULA_EMAIL_MODE=resend ;; *) NEBULA_EMAIL_MODE=skip ;; esac
fi
case $NEBULA_EMAIL_MODE in
  smtp)
    ask NEBULA_SMTP_HOST "SMTP host (e.g. smtp.gmail.com)"
    ask NEBULA_SMTP_PORT "SMTP port" 587
    ask NEBULA_SMTP_USERNAME "SMTP username" "$NEBULA_ADMIN_EMAIL"
    [ -s $SECRETS/smtp_password ] || ask NEBULA_SMTP_PASSWORD "SMTP password (hidden)" "" secret
    ask NEBULA_EMAIL_FROM "Send emails from" "Nebula VPN <$NEBULA_SMTP_USERNAME>"
    remember NEBULA_SMTP_HOST "$NEBULA_SMTP_HOST"; remember NEBULA_SMTP_PORT "$NEBULA_SMTP_PORT"
    remember NEBULA_SMTP_USERNAME "$NEBULA_SMTP_USERNAME" ;;
  resend)
    [ -s $SECRETS/resend_api_key ] || ask NEBULA_RESEND_API_KEY "Resend API key (hidden)" "" secret
    # Resend sends only from a domain verified in the Resend account, and
    # fails every email otherwise. People usually verify the parent domain.
    echo "The sender must be on a domain verified in your Resend account (Domains page)."
    parent=${NEBULA_DOMAIN#*.}; [[ $parent == *.* ]] || parent=$NEBULA_DOMAIN
    ask NEBULA_EMAIL_FROM "Send emails from" "Nebula VPN <no-reply@$parent>" ;;
  *) NEBULA_EMAIL_FROM=${NEBULA_EMAIL_FROM:-"Nebula VPN <no-reply@$NEBULA_DOMAIN>"} ;;
esac
remember NEBULA_EMAIL_MODE "$NEBULA_EMAIL_MODE"; remember NEBULA_EMAIL_FROM "$NEBULA_EMAIL_FROM"

step "Backups off this server"
if [ -z "${NEBULA_BACKUP_OFFSITE:-}" ] && [ -t 0 ]; then
  echo "Backups are encrypted and kept on this server; a copy elsewhere survives losing it."
  echo "  1) Backblaze B2 (or any S3-compatible bucket)"
  echo "  2) Keep them on this server only"
  ask NEBULA_BACKUP_OFFSITE "Choose 1 or 2" 1
fi
case ${NEBULA_BACKUP_OFFSITE:-local} in 1|b2) NEBULA_BACKUP_OFFSITE=b2 ;; *) NEBULA_BACKUP_OFFSITE=local ;; esac
if [ "$NEBULA_BACKUP_OFFSITE" = b2 ]; then
  ask NEBULA_BACKUP_B2_BUCKET "Bucket name"
  ask NEBULA_BACKUP_B2_ENDPOINT "S3 endpoint (e.g. https://s3.us-west-004.backblazeb2.com)"
  [ -s $SECRETS/b2_key_id ] || ask NEBULA_BACKUP_B2_KEY_ID "Application key ID"
  [ -s $SECRETS/b2_application_key ] || ask NEBULA_BACKUP_B2_APPLICATION_KEY "Application key (hidden)" "" secret
  remember NEBULA_BACKUP_B2_BUCKET "$NEBULA_BACKUP_B2_BUCKET"
  remember NEBULA_BACKUP_B2_ENDPOINT "$NEBULA_BACKUP_B2_ENDPOINT"
else
  warn "backups stay on this server only: if it is lost, so are they. Copy /var/backups/nebula elsewhere, or rerun and choose 1."
fi
remember NEBULA_BACKUP_OFFSITE "$NEBULA_BACKUP_OFFSITE"
fi

step "Network check"
if [ -z "${NEBULA_INSTALL_PROXY:-}" ] && \
   [ "$(curl -s -o /dev/null -m 20 -w '%{http_code}' https://files.pythonhosted.org/packages/ || true)" = 000 ]; then
  echo "This server cannot reach PyPI's download host, which the build needs."
  echo "Give an HTTP proxy that can (e.g. http://127.0.0.1:10809), or leave empty to try anyway."
  read -rp "HTTP proxy: " NEBULA_INSTALL_PROXY || true
fi
if [ -n "${NEBULA_INSTALL_PROXY:-}" ]; then remember NEBULA_INSTALL_PROXY "$NEBULA_INSTALL_PROXY"; ok "downloads go through $NEBULA_INSTALL_PROXY"; else ok "direct"; fi

# --- Packages and Docker -----------------------------------------------------

step "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y ca-certificates curl openssl nginx certbot wireguard-tools python3-venv unzip acl ufw age fail2ban unattended-upgrades >/dev/null
# Host hardening the first server got by hand (production-readiness audit H-1
# and M-5): fail2ban's sshd jail (on by default in Debian/Ubuntu), security
# updates installed daily, and swap on a small server with none.
systemctl enable --now fail2ban >/dev/null 2>&1 || warn "fail2ban did not start: journalctl -u fail2ban"
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
if [ -z "$(swapon --show --noheadings)" ] && [ "$(awk '/MemTotal/{print $2}' /proc/meminfo)" -lt 4194304 ] \
  && [ "$(df --output=avail -k / | tail -1)" -gt 6291456 ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
if [ -z "$JOIN_URL" ]; then
  if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    fetch https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh >/tmp/get-docker.log 2>&1 || die "Docker install failed; see /tmp/get-docker.log"
  fi
  systemctl enable --now docker >/dev/null 2>&1
  ok "$(docker --version)"
else
  ok "packages"
fi

# --- Configuration and secrets (generated once, never replaced) -------------

getent group nebula-secrets >/dev/null || groupadd --gid 9443 nebula-secrets
install -d -o root -g nebula-secrets -m 0750 $SECRETS
if [ -n "$JOIN_URL" ]; then
  [ -f $SECRETS/wireguard_server_private_key ] || (umask 077; wg genkey > $SECRETS/wireguard_server_private_key)
  chown root:nebula-secrets $SECRETS/*; chmod 0640 $SECRETS/*
else
step "Configuration"
rand() { openssl rand -hex 24; }
if [ ! -f $ETC/compose.env ]; then
  umask 077
  cat > $ETC/compose.env <<EOF
POSTGRES_DB=nebula
POSTGRES_SUPERUSER=postgres
POSTGRES_SUPERUSER_PASSWORD=$(rand)
NEBULA_DB_APP_USER=nebula_app
NEBULA_DB_APP_PASSWORD=$(rand)
NEBULA_DB_MIGRATOR_USER=nebula_migrator
NEBULA_DB_MIGRATOR_PASSWORD=$(rand)
NEBULA_REDIS_PASSWORD=$(rand)
NEBULA_JWT_KEY_ID=jwt-$(date +%Y-%m)
NEBULA_TOKEN_KEY_VERSION=1
NEBULA_MFA_KEY_VERSION=1
NEBULA_XRAY_KEY_VERSION=1
EOF
  umask 022
fi
# Settings that follow the answers above are rewritten on every run.
setenv() { sed -i "/^$1=/d" $ETC/compose.env; printf '%s=%s\n' "$1" "$2" >> $ETC/compose.env; }
setenv NEBULA_API_PUBLIC_URL "https://$APIHOST:8444"
setenv NEBULA_ADMIN_PUBLIC_URL "https://$PANEL:8444"
setenv NEBULA_ALLOWED_ORIGINS "https://$PANEL:8444"
setenv NEBULA_API_ROUTES "https://$APIHOST:8444,https://$NEBULA_DOMAIN:8445"
setenv NEBULA_EMAIL_FROM "$NEBULA_EMAIL_FROM"
# What the apps call this server; every install was "Nebula" before.
setenv NEBULA_DEPLOYMENT_NAME "$NEBULA_DOMAIN"
case $NEBULA_EMAIL_MODE in
  resend) setenv NEBULA_EMAIL_PROVIDER resend ;;
  smtp) setenv NEBULA_EMAIL_PROVIDER smtp; setenv NEBULA_SMTP_HOST "$NEBULA_SMTP_HOST"
        setenv NEBULA_SMTP_PORT "$NEBULA_SMTP_PORT"; setenv NEBULA_SMTP_USERNAME "$NEBULA_SMTP_USERNAME"
        setenv NEBULA_SMTP_STARTTLS "$([ "$NEBULA_SMTP_PORT" = 465 ] && echo false || echo true)" ;;
  # The worker needs a provider; this one is unroutable, so mail waits in the
  # outbox until email is configured.
  *) setenv NEBULA_EMAIL_PROVIDER smtp; setenv NEBULA_SMTP_HOST unset.invalid ;;
esac
chmod 0640 $ETC/compose.env
[ -n "${NEBULA_SMTP_PASSWORD:-}" ] && printf '%s' "$NEBULA_SMTP_PASSWORD" > $SECRETS/smtp_password
[ -n "${NEBULA_RESEND_API_KEY:-}" ] && printf '%s' "$NEBULA_RESEND_API_KEY" > $SECRETS/resend_api_key
touch $SECRETS/smtp_password $SECRETS/resend_api_key
[ -n "${NEBULA_BACKUP_B2_KEY_ID:-}" ] && (umask 077; printf '%s' "$NEBULA_BACKUP_B2_KEY_ID" > $SECRETS/b2_key_id)
[ -n "${NEBULA_BACKUP_B2_APPLICATION_KEY:-}" ] && (umask 077; printf '%s' "$NEBULA_BACKUP_B2_APPLICATION_KEY" > $SECRETS/b2_application_key)
ok "$ETC/compose.env"

# --- Images ------------------------------------------------------------------

step "Building the images (a few minutes the first time)"
# docker build rather than compose build: only it can give the build the
# host's network, which a proxy on 127.0.0.1 needs.
build() {
  local tag=$1 context=$2; shift 2
  docker build -q --network host -t "$tag" \
    ${NEBULA_INSTALL_PROXY:+--build-arg HTTP_PROXY=$NEBULA_INSTALL_PROXY --build-arg HTTPS_PROXY=$NEBULA_INSTALL_PROXY} \
    "$@" "$context" >/tmp/nebula-build.log 2>&1 || { tail -n 30 /tmp/nebula-build.log; die "building $tag failed"; }
}
build $PROJECT-api "$REPO/services/api"
for alias in migrate usage prune; do docker tag $PROJECT-api $PROJECT-$alias; done
build $PROJECT-worker "$REPO/services/worker"
build $PROJECT-admin "$REPO/apps/admin" --build-arg NEBULA_API_INTERNAL_URL=http://api:8000 \
  --build-arg NEBULA_ADMIN_ORIGIN="https://$PANEL:8444"
ok "images built"

keygen() { docker run --rm --user 0 --entrypoint nebula-api -v $SECRETS:/out $PROJECT-api "$@" >/dev/null; }
[ -f $SECRETS/jwt_private_key ] || keygen generate-jwt-signing-key --private-key-out /out/jwt_private_key --public-key-out /out/jwt_public_key
[ -f $SECRETS/token_pepper ] || keygen generate-symmetric-key --purpose token-pepper --out /out/token_pepper
[ -f $SECRETS/mfa_encryption_key ] || keygen generate-symmetric-key --purpose mfa-encryption --out /out/mfa_encryption_key
[ -f $SECRETS/xray_encryption_key ] || keygen generate-symmetric-key --purpose xray-encryption --out /out/xray_encryption_key
[ -f $SECRETS/wireguard_server_private_key ] || (umask 077; wg genkey > $SECRETS/wireguard_server_private_key)
chown root:nebula-secrets $SECRETS/*; chmod 0640 $SECRETS/*
ok "keys in $SECRETS"

if [ -n "$RESTORE_DIR" ]; then
  step "Restoring the database and state"
  # Before the API's first start, so it finds its identity rather than
  # generating a new one, and before migrate, which then has nothing to do.
  volume=$(compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["volumes"]["nebula-state"]["name"])')
  docker volume create "$volume" >/dev/null
  docker run --rm -i --user 0 --entrypoint tar -v "$volume:/state" $PROJECT-api -C /state -xf - < "$RESTORE_DIR/state.tar"
  compose up -d --no-build --wait postgres >/dev/null 2>&1 || die "the database did not start"
  compose exec -T postgres sh -c 'psql -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
    < "$RESTORE_DIR/postgres/postgres.sql" >/dev/null || die "loading the database dump failed"
  ok "database and installation identity restored"
fi

step "Starting the control plane"
compose up -d --no-build --wait --wait-timeout 300 >/tmp/nebula-up.log 2>&1 || {
  tail -n 20 /tmp/nebula-up.log; compose logs --tail 30 api; die "the stack did not become healthy"; }
# The worker reads the mail credential when it starts, and a changed key file
# alone does not make compose recreate it.
compose restart worker >/dev/null 2>&1
ok "database, API, worker and panel are running"
fi

# --- Certificate and web server ---------------------------------------------

step "DNS"
resolve() {
  { fetch -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$1&type=A" 2>/dev/null \
      | grep -oE '"data":"[0-9.]+"' | tail -1 | cut -d'"' -f4; } || true
}
dns_ok() {
  local h ip
  for h in "${NAMES[@]}"; do
    ip=$(resolve "$h"); [ -n "$ip" ] || ip=$(getent ahostsv4 "$h" | awk 'NR==1{print $1}')
    [ "$ip" = "$PUBLIC_IP" ] || { echo "  $h -> ${ip:-nothing} (needs $PUBLIC_IP)"; return 1; }
  done
}
until dns_ok; do
  cat <<EOF
Create these DNS records at your DNS provider (proxy/CDN off, "DNS only"):
  A  $NEBULA_DOMAIN     $PUBLIC_IP
EOF
  [ -n "$JOIN_URL" ] || echo "  A  *.$NEBULA_DOMAIN   $PUBLIC_IP"
  [ -t 0 ] || die "DNS is not ready"
  read -rp "Press Enter once they are saved (it can take a few minutes), or type skip: " answer
  [ "$answer" = skip ] && break
done
ok "names point at $PUBLIC_IP"

step "Certificate"
install -d /var/www/nebula-acme /etc/nginx/snippets
rm -f /etc/nginx/sites-enabled/default
# Names a censor's scanner cannot predict: every install used the same
# paths, gRPC service name and Hysteria2 decoy. A new install picks its own;
# one that already has agent.env keeps what its clients already use.
envget() { [ -f $ETC/agent.env ] && sed -n "s/^$1=//p" $ETC/agent.env | tail -1; return 0; }
# WireGuard's address range. A server that has one keeps it (wg0.conf first,
# then agent.env); a new one takes NEBULA_WG_CLIENT_POOL, or a /20 (4094
# devices). The server's address is the range's first one.
WG_ADDR=
# Under pipefail a missing file would end the install here.
[ ! -f /etc/wireguard/wg0.conf ] || WG_ADDR=$(sed -n 's/^Address *= *//p' /etc/wireguard/wg0.conf | head -1)
[ -n "$WG_ADDR" ] || WG_ADDR=$(envget NEBULA_WG_SERVER_ADDRESS)
if [ -z "$WG_ADDR" ]; then
  WG_ADDR=$(python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); assert n.version == 4 and n.is_private and n.prefixlen <= 29; print(f"{next(n.hosts())}/{n.prefixlen}")' \
    "${NEBULA_WG_CLIENT_POOL:-10.77.0.0/20}" 2>/dev/null) || die "NEBULA_WG_CLIENT_POOL must be a private IPv4 range like 10.77.0.0/20"
fi
WG_POOL=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$WG_ADDR")
if [ -f $ETC/agent.env ]; then
  XHTTP_PATH=$(envget NEBULA_XRAY_XHTTP_PATH); XHTTP_PATH=${XHTTP_PATH:-/xhttp}
  WS_PATH=$(envget NEBULA_XRAY_WS_PATH); WS_PATH=${WS_PATH:-/ws}
  GRPC_NAME=$(envget NEBULA_XRAY_GRPC_SERVICE_NAME); GRPC_NAME=${GRPC_NAME:-grpc}
  VMESS_WS_PATH=$(envget NEBULA_XRAY_VMESS_WS_PATH); VMESS_WS_PATH=${VMESS_WS_PATH:-/vw}
  DECOY=$(envget NEBULA_XRAY_HYSTERIA_MASQUERADE_URL); DECOY=${DECOY:-https://news.ycombinator.com}
else
  XHTTP_PATH=/$(openssl rand -hex 6); WS_PATH=/$(openssl rand -hex 6)
  GRPC_NAME=s$(openssl rand -hex 5); VMESS_WS_PATH=/$(openssl rand -hex 6)
  DECOYS=(https://www.wikipedia.org https://www.mozilla.org https://www.apple.com https://www.bing.com https://www.debian.org https://www.python.org https://www.gnu.org https://news.ycombinator.com)
  DECOY=${DECOYS[$(( $(od -An -N2 -tu2 /dev/urandom) % ${#DECOYS[@]} ))]}
fi
sed -e "s/panel.example.com/$PANEL/g" -e "s/api.example.com/$APIHOST/g" -e "s/vpn.example.com/$NEBULA_DOMAIN/g" \
  "$REPO/infrastructure/nginx/nebula-8444.conf" > /etc/nginx/sites-available/nebula
# A joined server serves no panel or API: its site is the port-80 block alone.
[ -n "$JOIN_URL" ] && awk '/^server \{/{n++} n<=1' /etc/nginx/sites-available/nebula \
  | sed "s/server_name .*;/server_name $NEBULA_DOMAIN;/" > /tmp/nebula-site && mv /tmp/nebula-site /etc/nginx/sites-available/nebula
if [ ! -f $CERT/fullchain.pem ]; then
  # Only the port-80 block until the certificate exists: nginx refuses to load
  # a server block whose certificate file is missing.
  awk '/^server \{/{n++} n<=1' /etc/nginx/sites-available/nebula > /etc/nginx/sites-available/nebula-acme
  ln -sf /etc/nginx/sites-available/nebula-acme /etc/nginx/sites-enabled/nebula
  nginx -t >/dev/null 2>&1 && systemctl reload-or-restart nginx
  domains=(); for h in "${NAMES[@]}"; do domains+=(-d "$h"); done
  certbot certonly --webroot -w /var/www/nebula-acme --cert-name "$CERTNAME" "${domains[@]}" \
    --email "$NEBULA_ADMIN_EMAIL" --agree-tos --no-eff-email --non-interactive -q \
    || die "the certificate could not be issued. Port 80 must be reachable from the internet, and the
       DNS records above must point here. (A domain filtered in the server's own country cannot pass.)"
  rm -f /etc/nginx/sites-available/nebula-acme
fi
ln -sf /etc/nginx/sites-available/nebula /etc/nginx/sites-enabled/nebula
cp "$REPO/infrastructure/nginx/nebula-ratelimit.conf" /etc/nginx/conf.d/
cp "$REPO/infrastructure/nginx/cloudflare-real-ip.conf" /etc/nginx/snippets/
sed -e "s/vpn.example.com/$NEBULA_DOMAIN/g" -e "s#live/$NEBULA_DOMAIN/#live/$CERTNAME/#g" -e "s/ cdn.example.com//" \
  -e "s#location /xhttp {#location $XHTTP_PATH {#" -e "s#location /ws {#location $WS_PATH {#" -e "s#location /grpc/ {#location /$GRPC_NAME/ {#" \
  "$REPO/infrastructure/nginx/xray-8445.conf" > /etc/nginx/conf.d/xray-8445.conf
nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx rejected the configuration"; }
systemctl enable -q nginx; systemctl reload-or-restart nginx
ok "certificate for ${NAMES[*]}"

# --- VPN engines and agent ----------------------------------------------------

step "VPN engines"
id nebula-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin nebula-agent
id nebula-xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin nebula-xray
usermod -aG nebula-secrets nebula-agent; usermod -aG nebula-agent nebula-xray
install -d -o nebula-agent -g nebula-agent -m 0700 /var/lib/nebula/wireguard
install -d -o nebula-agent -g nebula-agent -m 0750 /etc/nebula/xray
install -d -o nebula-agent -g root -m 2750 /etc/nebula/hysteria
# A rerun brings an older Xray up to the pinned one; install(1) replaces the
# file rather than writing into the running binary.
if [ "$(/usr/local/bin/xray version 2>/dev/null | awk 'NR==1{print $2}')" != "$XRAY_VERSION" ]; then
  zip=$([ $ARCH = amd64 ] && echo Xray-linux-64.zip || echo Xray-linux-arm64-v8a.zip)
  fetch -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/$zip"
  echo "${XRAY_SHA[$ARCH]}  /tmp/xray.zip" | sha256sum -c --quiet || die "Xray download failed its checksum"
  rm -rf /tmp/xray-new; unzip -oq /tmp/xray.zip xray -d /tmp/xray-new
  install -m 0755 /tmp/xray-new/xray /usr/local/bin/xray
  ! systemctl is-active -q nebula-xray || systemctl restart nebula-xray
fi
if [ ! -x /usr/local/bin/hysteria ]; then
  fetch -o /tmp/hysteria "https://github.com/apernet/hysteria/releases/download/app/v$HYSTERIA_VERSION/hysteria-linux-$ARCH"
  echo "${HYSTERIA_SHA[$ARCH]}  /tmp/hysteria" | sha256sum -c --quiet || die "Hysteria2 download failed its checksum"
  install -m 0755 /tmp/hysteria /usr/local/bin/hysteria
fi
# Xray and the agent read the certificate as themselves, not as root.
for u in nebula-xray nebula-agent; do
  setfacl -m u:$u:x /etc/letsencrypt/live /etc/letsencrypt/archive
  setfacl -R -m u:$u:rX -m d:u:$u:rX "/etc/letsencrypt/live/$CERTNAME" "/etc/letsencrypt/archive/$CERTNAME"
done
install -m 0644 "$REPO/infrastructure/polkit/49-nebula-xray-agent.rules" /etc/polkit-1/rules.d/
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/nebula.sh <<'EOF'
#!/bin/sh
# Xray and Hysteria2 read the certificate only when they start.
systemctl reload nginx; systemctl restart nebula-xray nebula-hysteria
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/nebula.sh
if [ ! -f /etc/wireguard/wg0.conf ]; then
  umask 077
  printf '[Interface]\nAddress = %s\nListenPort = 51820\nPostUp = wg set %%i private-key %s\n' \
    "$WG_ADDR" $SECRETS/wireguard_server_private_key > /etc/wireguard/wg0.conf
  umask 022
fi
systemctl enable --now wg-quick@wg0 >/dev/null 2>&1
ok "Xray $(/usr/local/bin/xray version | awk 'NR==1{print $2}'), Hysteria2, WireGuard"

step "Firewall"
# awk reads to the end: one that exits early SIGPIPEs sshd, and pipefail
# then ends the whole install (seen 2026-10-26, exit 141).
# sshd -T can fail (exit 255 with no /run/sshd, e.g. socket-activated ssh);
# then the Port lines of its config decide, so a custom port stays open.
SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{p=$2} END{print p}' || true)
[ -n "$SSH_PORT" ] || SSH_PORT=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
  | awk 'tolower($1)=="port"{p=$2} END{print p}' || true)
SSH_PORT=${SSH_PORT:-22}
ufw allow "$SSH_PORT/tcp" comment ssh >/dev/null
for p in 80/tcp 8445/tcp 8447/tcp 8448/tcp 8449/tcp 8450/udp 51820/udp; do ufw allow $p comment nebula >/dev/null; done
if [ -n "$JOIN_URL" ]; then
  # The control plane reaches this agent over the internet; only it may.
  host=${JOIN_URL#https://}; host=${host%%[:/]*}
  CONTROL_IP=$(resolve "$host"); [ -n "$CONTROL_IP" ] || CONTROL_IP=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}')
  [ -n "$CONTROL_IP" ] || die "could not find the address of $host"
  ufw allow from "$CONTROL_IP" to any port 9443 proto tcp comment "nebula agent, control plane" >/dev/null
else
  ufw allow 8444/tcp comment nebula >/dev/null
  ufw allow from 172.30.101.0/24 to any port 9443 proto tcp comment "nebula agent" >/dev/null
fi
# Tunnelled users connect out as nebula-xray; refuse it this host and private
# networks, above ufw's loopback accept (docs/runbooks/deployment.md).
if ! grep -q 'uid-owner nebula-xray' /etc/ufw/before.rules; then
  rules=""; for n in 127.0.0.0/8 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15; do
    rules+="-A ufw-before-output -m owner --uid-owner nebula-xray -m conntrack --ctstate NEW -d $n -j REJECT\n"; done
  awk -v r="$rules" '/^-A ufw-before-output -o lo -j ACCEPT/{printf "%s", r} {print}' /etc/ufw/before.rules > /tmp/ufw-before && cat /tmp/ufw-before > /etc/ufw/before.rules
  rules=""; for n in ::1/128 fc00::/7 fe80::/10; do
    rules+="-A ufw6-before-output -m owner --uid-owner nebula-xray -m conntrack --ctstate NEW -d $n -j REJECT\n"; done
  awk -v r="$rules" '/^-A ufw6-before-output -o lo -j ACCEPT/{printf "%s", r} {print}' /etc/ufw/before6.rules > /tmp/ufw-before6 && cat /tmp/ufw-before6 > /etc/ufw/before6.rules
fi
# WireGuard clients reach the internet: forwarding, NAT on the outgoing
# interface and a ufw route. Without them a fresh server's WireGuard carried
# nothing (the first server was fixed by hand). Clients may not reach this
# host, private and Docker networks, the metadata service or each other --
# the same list the agent gives Xray and Hysteria2 (drivers/egress.py).
WAN=$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") d = $(i + 1)} END {print d}')
[ -n "$WAN" ] || die "no default route: cannot tell which interface WireGuard clients leave by"
wireguard_routing "$WAN" /etc/ufw/before.rules
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-nebula-forward.conf
sysctl -q -p /etc/sysctl.d/99-nebula-forward.conf
sed -i 's|^#\?net/ipv4/ip_forward=.*|net/ipv4/ip_forward=1|' /etc/ufw/sysctl.conf
ufw route allow in on wg0 out on "$WAN" comment nebula-wireguard >/dev/null
ufw --force enable >/dev/null; ufw reload >/dev/null
if [ -n "$JOIN_URL" ]; then opened="9443 from $CONTROL_IP"; else opened="8444"; fi
ok "open: ssh ($SSH_PORT), 80, $opened, 8445, 8447-8449, 8450/udp, 51820/udp"

step "VPN agent"
if [ ! -x /opt/nebula-vpn-agent/.venv/bin/nebula-agent-serve ]; then
  python3 -m venv /opt/nebula-vpn-agent/.venv
fi
# Dependencies only as pinned and hashed in requirements.lock; the agent
# itself is built from the checkout with the build backend from that lock.
{ HTTPS_PROXY=${NEBULA_INSTALL_PROXY:-} /opt/nebula-vpn-agent/.venv/bin/pip install -q --require-hashes \
    -r "$REPO/services/vpn-agent/requirements.lock" \
  && /opt/nebula-vpn-agent/.venv/bin/pip install -q --no-deps --no-build-isolation "$REPO/services/vpn-agent"; } \
  >/tmp/nebula-agent-pip.log 2>&1 || { tail -n 20 /tmp/nebula-agent-pip.log; die "installing the agent failed"; }
if [ ! -f $ETC/agent.env ]; then
  umask 027
  cat > $ETC/agent.env <<EOF
NEBULA_ENV=production
NEBULA_WG_DRIVER=native
NEBULA_WG_INTERFACE=wg0
NEBULA_AGENT_BIND_HOST=$([ -n "$JOIN_URL" ] && echo 0.0.0.0 || echo 172.30.101.1)
NEBULA_AGENT_BIND_PORT=9443
NEBULA_WG_SERVER_PRIVATE_KEY_FILE=$SECRETS/wireguard_server_private_key
NEBULA_AGENT_TLS_CERT_FILE=$SECRETS/agent_tls_cert
NEBULA_AGENT_TLS_KEY_FILE=$SECRETS/agent_tls_key
NEBULA_AGENT_TRUSTED_CLIENT_CA_FILE=$SECRETS/agent_ca
NEBULA_WG_SERVER_ADDRESS=$WG_ADDR
NEBULA_WG_CLIENT_POOL=$WG_POOL
NEBULA_WG_LISTEN_PORT=51820
NEBULA_WG_PUBLIC_ENDPOINT=$PUBLIC_IP:51820
NEBULA_XRAY_ENABLED=true
NEBULA_XRAY_DRIVER=native
NEBULA_XRAY_PUBLIC_HOST=$NEBULA_DOMAIN
NEBULA_XRAY_PUBLIC_PORT=8445
NEBULA_XRAY_SNI=$NEBULA_DOMAIN
NEBULA_XRAY_GRPC_ENABLED=true
NEBULA_XRAY_WS_ENABLED=true
NEBULA_XRAY_TCP_ENABLED=true
NEBULA_XRAY_HYSTERIA_ENABLED=true
NEBULA_XRAY_HYSTERIA_OBFS_PASSWORD=$(openssl rand -hex 16)
NEBULA_XRAY_XHTTP_PATH=$XHTTP_PATH
NEBULA_XRAY_WS_PATH=$WS_PATH
NEBULA_XRAY_GRPC_SERVICE_NAME=$GRPC_NAME
NEBULA_XRAY_VMESS_WS_PATH=$VMESS_WS_PATH
NEBULA_XRAY_HYSTERIA_MASQUERADE_URL=$DECOY
NEBULA_XRAY_TLS_CERT_FILE=$CERT/fullchain.pem
NEBULA_XRAY_TLS_KEY_FILE=$CERT/privkey.pem
EOF
  umask 022
fi
# --- Protocols and ports ------------------------------------------------------
# Every setting lives in agent.env, which the agent renders Xray and Hysteria2
# from: editing Xray's config by hand is overwritten at the next change.
agentget() { sed -n "s/^$1=//p" $ETC/agent.env | tail -1; }
agentset() { sed -i "/^$1=/d" $ETC/agent.env; printf '%s=%s\n' "$1" "$2" >> $ETC/agent.env; }
# name | enable key | port key | default port | proto | profile codes
PROTOCOLS=(
  "gRPC|NEBULA_XRAY_GRPC_ENABLED|NEBULA_XRAY_GRPC_PORT|8447|tcp|vless-grpc-tls"
  "WebSocket|NEBULA_XRAY_WS_ENABLED|NEBULA_XRAY_WS_PORT|8448|tcp|vless-ws-tls"
  "TCP+TLS|NEBULA_XRAY_TCP_ENABLED|NEBULA_XRAY_TCP_PORT|8449|tcp|vless-tcp-tls"
  "Hysteria2|NEBULA_XRAY_HYSTERIA_ENABLED|NEBULA_XRAY_HYSTERIA_PORT|8450|udp|hysteria2"
  "Shadowsocks-2022 (no TLS)|NEBULA_XRAY_SS2022_ENABLED|NEBULA_XRAY_SS2022_PORT|8451|both|shadowsocks-2022"
  "VLESS Encryption (no TLS)|NEBULA_XRAY_VLESSENC_ENABLED|NEBULA_XRAY_VLESSENC_PORT|8453|tcp|vless-enc"
  "VMess raw + WebSocket (no TLS)|NEBULA_XRAY_VMESS_ENABLED|NEBULA_XRAY_VMESS_PORT|8454|tcp|vmess-raw vmess-ws"
)
ENABLE_CODES=() DISABLE_CODES=() OPEN_PORTS=() CLOSE_PORTS=()
newport="" xhttp="" wgport=""
if [ -n "$CONFIGURE" ]; then
  [ -t 0 ] || die "--configure asks questions; run it in a terminal"
  step "Protocols and ports"
  echo "Enter keeps what is set now. XHTTP (through nginx) and WireGuard are always on."
  yes_no() { local a; read -rp "$1 [$2]: " a; a=${a:-$2}; [[ $a =~ ^[Yy] ]]; }
  ask_port() {
    local a; read -rp "  port [$2]: " a; a=${a:-$2}
    [[ $a =~ ^[0-9]+$ ]] && [ "$a" -ge 1 ] && [ "$a" -le 65535 ] || die "'$a' is not a port"
    printf -v "$1" '%s' "$a"
  }
  for entry in "${PROTOCOLS[@]}"; do
    IFS='|' read -r name key portkey default proto codes <<<"$entry"
    was=$(agentget "$key"); was=${was:-false}
    oldport=$(agentget "$portkey"); oldport=${oldport:-$default}
    if yes_no "$name" "$([ "$was" = true ] && echo Y || echo n)"; then
      ask_port newport "$oldport"
      agentset "$key" true; agentset "$portkey" "$newport"
      case $key in
        NEBULA_XRAY_SS2022_ENABLED) [ -n "$(agentget NEBULA_XRAY_SS2022_SERVER_KEY)" ] \
          || agentset NEBULA_XRAY_SS2022_SERVER_KEY "$(openssl rand -base64 16)" ;;
        NEBULA_XRAY_VLESSENC_ENABLED) if [ -z "$(agentget NEBULA_XRAY_VLESSENC_DECRYPTION)" ]; then
            pair=$(/usr/local/bin/xray vlessenc 2>/dev/null | grep -oE 'mlkem768x25519plus\.[^" ]+')
            agentset NEBULA_XRAY_VLESSENC_DECRYPTION "$(sed -n 1p <<<"$pair")"
            agentset NEBULA_XRAY_VLESSENC_ENCRYPTION "$(sed -n 2p <<<"$pair")"
          fi ;;
      esac
      [ "$was" = true ] && [ "$oldport" != "$newport" ] && CLOSE_PORTS+=("$oldport/$proto")
      OPEN_PORTS+=("$newport/$proto")
      [ "$key" = NEBULA_XRAY_VMESS_ENABLED ] && OPEN_PORTS+=("$(( newport + 1 ))/tcp") \
        && agentset NEBULA_XRAY_VMESS_WS_PORT "$(( newport + 1 ))"
      if [ "$was" != true ]; then read -ra list <<<"$codes"; ENABLE_CODES+=("${list[@]}"); fi
    else
      agentset "$key" false
      if [ "$was" = true ]; then CLOSE_PORTS+=("$oldport/$proto"); read -ra list <<<"$codes"; DISABLE_CODES+=("${list[@]}"); fi
    fi
  done
  oldxhttp=$(agentget NEBULA_XRAY_PUBLIC_PORT); oldxhttp=${oldxhttp:-8445}
  echo "XHTTP"; ask_port xhttp "$oldxhttp"
  if [ "$xhttp" != "$oldxhttp" ]; then
    agentset NEBULA_XRAY_PUBLIC_PORT "$xhttp"
    sed -i "s/listen \(\[::\]:\)\?$oldxhttp ssl/listen \1$xhttp ssl/" /etc/nginx/conf.d/xray-8445.conf
    CLOSE_PORTS+=("$oldxhttp/tcp"); OPEN_PORTS+=("$xhttp/tcp")
  fi
  oldwg=$(agentget NEBULA_WG_LISTEN_PORT); oldwg=${oldwg:-51820}
  echo "WireGuard"; ask_port wgport "$oldwg"
  if [ "$wgport" != "$oldwg" ]; then
    agentset NEBULA_WG_LISTEN_PORT "$wgport"
    sed -i "s/^ListenPort = .*/ListenPort = $wgport/" /etc/wireguard/wg0.conf
    systemctl restart wg-quick@wg0
    CLOSE_PORTS+=("$oldwg/udp"); OPEN_PORTS+=("$wgport/udp")
  fi
fi

# A restore onto a new server, or a changed address: WireGuard clients dial this.
WG_PORT=$(agentget NEBULA_WG_LISTEN_PORT); WG_PORT=${WG_PORT:-51820}
sed -i "s#^NEBULA_WG_PUBLIC_ENDPOINT=.*#NEBULA_WG_PUBLIC_ENDPOINT=$PUBLIC_IP:$WG_PORT#" $ETC/agent.env
chown root:nebula-agent $ETC/agent.env; chmod 0640 $ETC/agent.env
cp "$REPO/services/vpn-agent/deploy/nebula-vpn-agent.service" "$REPO"/infrastructure/systemd/nebula-{xray,hysteria}.service \
  "$REPO/infrastructure/systemd/nebula-alert@.service" /etc/systemd/system/
systemctl daemon-reload
if [ ! -f $SECRETS/agent_tls_key ]; then
  if [ -n "$JOIN_URL" ]; then
    [ -n "$JOIN_TOKEN" ] || die "this server is not enrolled yet; run it with --join <API address> --token <token>"
    token=$JOIN_TOKEN control_plane=$JOIN_URL agent_host=$PUBLIC_IP
  else
    token=$(api create-enrollment-token --label "${NEBULA_DOMAIN%%.*}" | grep -oE 'v1\.[A-Za-z0-9._-]+')
    control_plane="https://$APIHOST:8444" agent_host=172.30.101.1
  fi
  enrolled=$( set -a; . $ETC/agent.env; set +a
    printf '%s' "$token" | /opt/nebula-vpn-agent/.venv/bin/nebula-agent-enroll \
      --control-plane "$control_plane" --public-host "$NEBULA_DOMAIN" --agent-host "$agent_host" ) \
    || die "enrolling this server failed: the token may be used or expired (make a new one with Add server)"
  # Its code on the control plane, for the commands --configure prints.
  remember NEBULA_SERVER_CODE "$(sed -n 's/^enrolled as //p' <<<"$enrolled")"
  chmod 0644 $SECRETS/agent_ca $SECRETS/agent_tls_cert
fi
for p in "${CLOSE_PORTS[@]}"; do
  for one in $( [ "${p#*/}" = both ] && echo "${p%/*}/tcp ${p%/*}/udp" || echo "$p" ); do
    ufw delete allow "$one" >/dev/null 2>&1 || true
  done
done
for p in "${OPEN_PORTS[@]}"; do
  for one in $( [ "${p#*/}" = both ] && echo "${p%/*}/tcp ${p%/*}/udp" || echo "$p" ); do
    ufw allow "$one" comment nebula >/dev/null
  done
done
[ -n "$CONFIGURE" ] && { nginx -t >/dev/null 2>&1 && systemctl reload-or-restart nginx; ufw reload >/dev/null; }
systemctl enable nebula-vpn-agent >/dev/null 2>&1; systemctl restart nebula-vpn-agent
for _ in $(seq 1 30); do [ -f /etc/nebula/xray/config.json ] && break; sleep 1; done
systemctl enable --now nebula-xray nebula-hysteria >/dev/null 2>&1
ok "agent running; server enrolled${JOIN_URL:+ with $JOIN_URL}"

if [ -z "$JOIN_URL" ]; then
step "Protocols"
for s in wireguard-protocol wireguard-adblock-profile vless-xhttp-protocol vless-xhttp-adblock-protocol \
         vless-grpc-protocol vless-grpc-adblock-protocol vless-ws-protocol vless-ws-adblock-protocol \
         vless-tcp-protocol vless-tcp-adblock-protocol hysteria2-protocol hysteria2-adblock-protocol; do
  api "seed-$s" >/dev/null
done
server=$(compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select code from vpn_servers order by created_at limit 1"' | tr -d '\r')
for p in wireguard-native wireguard-native-adblock vless-xhttp-tls vless-xhttp-tls-adblock vless-grpc-tls vless-grpc-tls-adblock \
         vless-ws-tls vless-ws-tls-adblock vless-tcp-tls vless-tcp-tls-adblock hysteria2 hysteria2-adblock; do
  api enable-server-capability --server-code "$server" --protocol-profile-code "$p" >/dev/null
done
ok "12 protocol profiles on server $server"
fi
if [ -n "$CONFIGURE" ] && [ -z "$JOIN_URL" ]; then
  server=$(compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select code from vpn_servers where agent_host = '"'"'172.30.101.1'"'"' limit 1"' | tr -d '\r')
  if printf '%s
' "${ENABLE_CODES[@]}" | grep -q shadowsocks; then api seed-ss2022-protocol >/dev/null; fi
  if printf '%s
' "${ENABLE_CODES[@]}" | grep -qE 'vless-enc|vmess'; then api seed-direct-protocols >/dev/null; fi
  for code in "${ENABLE_CODES[@]}"; do
    api enable-server-capability --server-code "$server" --protocol-profile-code "$code" >/dev/null
    api enable-server-capability --server-code "$server" --protocol-profile-code "$code-adblock" >/dev/null 2>&1 || true
  done
  for code in "${DISABLE_CODES[@]}"; do
    api disable-server-capability --server-code "$server" --protocol-profile-code "$code" >/dev/null
    api disable-server-capability --server-code "$server" --protocol-profile-code "$code-adblock" >/dev/null 2>&1 || true
  done
  ok "the control plane offers what $server serves"
elif [ -n "$CONFIGURE" ]; then
  if [ ${#ENABLE_CODES[@]} -gt 0 ] || [ ${#DISABLE_CODES[@]} -gt 0 ]; then
    warn "on the control plane (in its API container), turn the changed protocols on or off:"
  fi
  for code in "${ENABLE_CODES[@]}"; do echo "    nebula-api enable-server-capability --server-code ${NEBULA_SERVER_CODE:-<this server>} --protocol-profile-code $code"; done
  for code in "${DISABLE_CODES[@]}"; do echo "    nebula-api disable-server-capability --server-code ${NEBULA_SERVER_CODE:-<this server>} --protocol-profile-code $code"; done
fi

step "Checking what clients will see"
# Right after the restarts above, a connection to this host's own address can
# go unanswered for a few seconds (every endpoint answers a minute later), so
# only a failure that lasts is reported.
for attempt in 1 2 3; do
  if report=$( set -a; . $ETC/agent.env; set +a; /opt/nebula-vpn-agent/.venv/bin/nebula-agent-check 2>&1 ); then break; fi
  [ $attempt = 3 ] || sleep 15
done
grep -E '^\[' <<<"$report" || true
grep -q '^\[FAIL' <<<"$report" && warn "an endpoint did not answer; check the firewall and nginx, then rerun"

if [ -n "$JOIN_URL" ]; then
  cat <<EOF

${green}${bold}This server has joined.${reset}

  It appears in the admin panel under Server health. Assign it to users
  there; its protocols were enabled when it enrolled.
  To update later:  sudo ./install.sh --update

EOF
  exit 0
fi

# --- Backups -------------------------------------------------------------------

step "Backups"
NEW_BACKUP_KEY=""
if ! grep -qs '^NEBULA_BACKUP_AGE_RECIPIENT=' $ETC/backup.env; then
  if [ -f $ETC/backup-key.txt ]; then
    NEW_BACKUP_KEY=$ETC/backup-key.txt
  else
    # A new path: age-keygen will not write into an existing file.
    NEW_BACKUP_KEY=$(mktemp -d)/backup-key.txt
    (umask 077; age-keygen -o "$NEW_BACKUP_KEY" 2>/dev/null)
  fi
  printf 'NEBULA_BACKUP_AGE_RECIPIENT=%s\n' "$(age-keygen -y "$NEW_BACKUP_KEY")" >> $ETC/backup.env
  chmod 0640 $ETC/backup.env
fi
backupset() { sed -i "/^$1=/d" $ETC/backup.env; printf '%s=%s\n' "$1" "$2" >> $ETC/backup.env; }
if [ "${NEBULA_BACKUP_OFFSITE:-local}" = b2 ]; then
  command -v aws >/dev/null || apt-get -qq install -y awscli >/dev/null 2>&1 || {
    python3 -m venv /opt/nebula-awscli && /opt/nebula-awscli/bin/pip install -q awscli       && ln -sf /opt/nebula-awscli/bin/aws /usr/local/bin/aws; } || warn "could not install the AWS CLI; uploads will fail until it is"
  backupset NEBULA_BACKUP_B2_BUCKET "$NEBULA_BACKUP_B2_BUCKET"
  backupset NEBULA_BACKUP_B2_ENDPOINT "$NEBULA_BACKUP_B2_ENDPOINT"
  backupset NEBULA_BACKUP_B2_KEY_ID_FILE $SECRETS/b2_key_id
  backupset NEBULA_BACKUP_B2_APPLICATION_KEY_FILE $SECRETS/b2_application_key
fi
for unit in nebula-backup.service nebula-backup.timer; do
  sed "s#/opt/nebula#$REPO#g" "$REPO/infrastructure/systemd/$unit" > /etc/systemd/system/$unit
done
systemctl daemon-reload; systemctl enable --now nebula-backup.timer >/dev/null 2>&1
systemctl start nebula-backup.service || warn "the first backup failed: journalctl -u nebula-backup.service"
latest=$(ls -t /var/backups/nebula/nebula-backup-*.tar.gz.age 2>/dev/null | head -1 || true)
ok "daily, encrypted, kept 14 days in /var/backups/nebula${latest:+ (latest: $(basename "$latest"))}"

# --- The administrator --------------------------------------------------------

step "Administrator account"
if [ "$(compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select count(*) > 0 from admin_users"' | tr -d '\r')" = t ]; then
  ok "an administrator already exists"
elif [ -t 0 ]; then
  echo "Choose the password for $NEBULA_ADMIN_EMAIL (at least 12 characters):"
  for _ in 1 2 3; do compose exec api nebula-api seed-admin --email "$NEBULA_ADMIN_EMAIL" && break; done
else
  warn "no terminal; create the administrator with:"
  echo "  docker compose -p $PROJECT --env-file $ETC/compose.env -f $COMPOSE_FILE exec api nebula-api seed-admin --email $NEBULA_ADMIN_EMAIL"
fi

# --- Email check ----------------------------------------------------------------
# A wrong key, sender or password shows here, not at the first sign-up.

if [ "$NEBULA_EMAIL_MODE" != skip ] && [ -t 0 ]; then
  step "Email check"
  read -rp "Send a test email to $NEBULA_ADMIN_EMAIL now? [Y/n]: " send_test
  if [[ ${send_test:-Y} =~ ^[Yy] ]]; then
    if compose exec -T worker python -m nebula_worker.send_test "$NEBULA_ADMIN_EMAIL"; then
      ok "sent; check the inbox (and spam) of $NEBULA_ADMIN_EMAIL"
    else
      warn "not sent; rerun sudo ./install.sh and answer y to 'Change it?' under Email delivery"
    fi
  fi
fi

cat <<EOF

${green}${bold}Nebula is installed.${reset}

  Admin panel   https://$PANEL:8444   (sign in as $NEBULA_ADMIN_EMAIL)
  App server    https://$APIHOST:8444  (the app's "Connect to your server" screen;
                the panel also shows it as a pairing link and QR code)

EOF
[ "$NEBULA_EMAIL_MODE" = skip ] && echo "  Email is not set up yet; people cannot get activation links. Rerun ./install.sh to add it."
echo "  To update later:  sudo ./install.sh --update"
echo "  To rebuild after losing this server:  sudo ./install.sh --restore <backup file>"
[ -n "$RESTORE_DIR" ] && rm -rf "$RESTORE_DIR"

LEFT_KEY=${NEW_BACKUP_KEY:-}
[ -z "$LEFT_KEY" ] && [ -f $ETC/backup-key.txt ] && LEFT_KEY=$ETC/backup-key.txt
if [ -n "$LEFT_KEY" ] && [ -t 0 ]; then
  cat <<EOF

${yellow}${bold}One thing only you can do: save the backup key.${reset}
Backups are encrypted with it, and it is the only way to open them. Keep it in
two places other than this server (a password manager and a printout).

  $(grep '^AGE-SECRET-KEY' "$LEFT_KEY")

It is then deleted from this server: a copy here would open every backup to
whoever takes the server.
EOF
  read -rp "Type 'saved' once it is stored elsewhere: " saved
  if [ "$saved" = saved ]; then
    shred -u "$LEFT_KEY" 2>/dev/null || rm -f "$LEFT_KEY"
    ok "backup key deleted from this server"
  else
    [ "$LEFT_KEY" = $ETC/backup-key.txt ] || install -m 0600 "$LEFT_KEY" $ETC/backup-key.txt
    [ "$LEFT_KEY" = $ETC/backup-key.txt ] || rm -f "$LEFT_KEY"
    warn "the backup key stays in $ETC/backup-key.txt; rerun ./install.sh to save and delete it"
  fi
elif [ -n "${NEW_BACKUP_KEY:-}" ] && [ "$NEW_BACKUP_KEY" != $ETC/backup-key.txt ]; then
  # No terminal to show it on: kept, so it is not lost, until a rerun.
  install -m 0600 "$NEW_BACKUP_KEY" $ETC/backup-key.txt; rm -f "$NEW_BACKUP_KEY"
  warn "the backup key is in $ETC/backup-key.txt; copy it off this server, then rerun ./install.sh to delete it"
fi
