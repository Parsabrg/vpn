"""Validated runtime configuration for the public API."""

import re
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Matches services/vpn-agent's Settings.xray_xhttp_path validator exactly.
_XHTTP_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9/_-]{0,254}$")


class Settings(BaseSettings):
    """API settings loaded exclusively from explicit `NEBULA_*` variables."""

    model_config = SettingsConfigDict(
        env_prefix="NEBULA_",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    env: Environment = "development"
    log_level: LogLevel = "INFO"
    api_public_url: str = "http://localhost:8000"
    # The Cloudflare-proxied hostname clients fall back to when the server's
    # own address is blocked; empty disables the route. Comma-separated for
    # more than one (another CDN's name too). See nebula_api/cdn.py.
    cdn_host: str = ""
    # Names on a web host (Vercel, Netlify) whose rewrite forwards plain HTTP
    # requests here; only XHTTP crosses one. Comma-separated. See cdn.py.
    front_hosts: str = ""
    # The servers behind NEBULA_CDN_HOST, by code, comma-separated. Empty means
    # every server, which is right while there is one. With a second server the
    # CDN name still points at the first, and a tunnel to the second sent
    # through it reached a server that did not know its credentials.
    cdn_servers: str = ""

    def behind_cdn(self, server_code: str) -> bool:
        codes = {code.strip() for code in self.cdn_servers.split(",") if code.strip()}
        return not codes or server_code in codes

    # The certificate authority behind this API's TLS certificate, when it is
    # not one clients already trust (an install reached by IP address with a
    # CA of its own). Served in the pairing record so a client can pin it.
    # Unset means a publicly trusted certificate. See pairing.py.
    pairing_ca_file: Path | None = None
    # Xray echConfigList handed out with tunnels through the CDN (Cloudflare
    # publishes one ECH key for every proxied name, under this public name).
    # Empty turns it off. See cdn.py.
    cdn_ech: str = "cloudflare-ech.com+udp://1.1.1.1"
    # Every address this API answers on, in the order a client should try
    # them, comma-separated. Served by /v1/routes so an address added later
    # reaches installed apps without a new build. See api_routes.py.
    api_routes: str = ""
    # The newest published client version (`0.1.24`), served by
    # /v1/client/release to apps that cannot read the private repository's
    # releases. Empty: nothing to offer. See client_release.py.
    client_latest_version: str = ""
    # The DNS address Xray clients are told to use: a reserved one the agent
    # redirects to this deployment's own resolver (roadmap 26; the agent's
    # NEBULA_XRAY_DNS_REDIRECT names the same address). Empty: clients
    # keep their own default.
    xray_client_dns: str = ""
    admin_public_url: str = "http://localhost:3000"
    allowed_origins: str = "http://localhost:3000"
    max_request_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    database_url: SecretStr = Field(
        default=SecretStr(
            "postgresql+psycopg://nebula_app:replace-local-only@localhost:5432/nebula"
        ),
        repr=False,
    )
    migration_database_url: SecretStr | None = Field(default=None, repr=False)
    database_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)
    database_statement_timeout_ms: int = Field(default=5_000, ge=100, le=30_000)
    readiness_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    redis_url: SecretStr = Field(default=SecretStr("redis://localhost:6379/0"), repr=False)

    jwt_issuer: str = Field(default="nebula-api", min_length=1, max_length=128)
    jwt_audience: str = Field(default="nebula-user", min_length=1, max_length=128)
    jwt_key_id: str = Field(default="v1", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
    jwt_private_key_file: Path | None = None
    jwt_public_key_file: Path | None = None
    jwt_previous_public_keys_dir: Path | None = None
    token_pepper_file: Path | None = None
    token_key_version: int = Field(default=1, ge=1, le=2_147_483_647)
    token_previous_peppers_dir: Path | None = None
    mfa_encryption_key_file: Path | None = None
    mfa_key_version: int = Field(default=1, ge=1, le=2_147_483_647)
    mfa_previous_encryption_keys_dir: Path | None = None
    xray_encryption_key_file: Path | None = None
    xray_key_version: int = Field(default=1, ge=1, le=2_147_483_647)
    xray_previous_encryption_keys_dir: Path | None = None

    # Writable state this installation generates for itself, as opposed to
    # /etc/nebula/secrets, which holds operator-provided key material and is
    # mounted read-only. Keeping the two apart is what lets the container
    # generate its own secrets without the directory holding the JWT and
    # encryption keys being writable by the service that reads them.
    #
    # Must be a persistent volume. Losing it loses the deployment secret,
    # which invalidates every outstanding node enrolment.
    state_dir: Path = Path("/var/lib/nebula")

    # Signs node enrollment tokens. Generated by `nebula-api initialize` if
    # absent, never overwritten, and never sent anywhere -- a node proves it
    # holds a token this signed, it never sees the key itself.
    deployment_secret_file: Path | None = None

    # The deployment's certificate authority, which signs node certificates
    # during enrolment. Generated by `nebula-api initialize` if absent. The
    # key never leaves this host: a node sends a public key and receives a
    # certificate, and cannot issue anything itself.
    node_ca_certificate_file: Path | None = None
    node_ca_key_file: Path | None = None

    @property
    def resolved_node_ca_certificate_file(self) -> Path:
        if self.node_ca_certificate_file is not None:
            return self.node_ca_certificate_file
        return self.state_dir / "node_ca_certificate"

    @property
    def resolved_node_ca_key_file(self) -> Path:
        if self.node_ca_key_file is not None:
            return self.node_ca_key_file
        return self.state_dir / "node_ca_key"

    # Signs only the control plane's own client certificate, so an agent can
    # trust it alone and refuse every node certificate (see pki.py).
    # Generated by `nebula-api initialize` if absent.
    @property
    def resolved_client_ca_certificate_file(self) -> Path:
        return self.state_dir / "client_ca_certificate"

    @property
    def resolved_client_ca_key_file(self) -> Path:
        return self.state_dir / "client_ca_key"

    @property
    def resolved_deployment_secret_file(self) -> Path:
        """Where the deployment secret lives, defaulting inside the state dir.

        Derived rather than defaulted to a literal path, so moving the state
        directory moves the secret with it instead of silently leaving it
        behind in a directory nothing mounts any more.
        """

        if self.deployment_secret_file is not None:
            return self.deployment_secret_file
        return self.state_dir / "deployment_secret"

    # The single XHTTP path shared by every client on the server's one
    # inbound (see agent_client/models.py's ProvisionXrayClientRequest
    # docstring) -- the agent never returns it, so the API must know it
    # independently. Mirrors services/vpn-agent's Settings.xray_xhttp_path
    # default; the two must be kept in sync by deployment configuration.
    xray_xhttp_path: str = "/xhttp"

    # The control plane's own end of the agent link. Left unset, these
    # resolve inside state_dir and `nebula-api initialize` issues them from
    # the control-plane CA -- which is what lets a fresh installation
    # talk to a node it enrolled without anybody generating a certificate by
    # hand. A deployment that manages its own material sets them explicitly
    # and nothing here touches those files.
    agent_client_cert_file: Path | None = None
    agent_client_key_file: Path | None = None
    agent_trusted_ca_file: Path | None = None

    @property
    def resolved_agent_client_cert_file(self) -> Path:
        if self.agent_client_cert_file is not None:
            return self.agent_client_cert_file
        return self.state_dir / "agent_client_certificate"

    @property
    def resolved_agent_client_key_file(self) -> Path:
        if self.agent_client_key_file is not None:
            return self.agent_client_key_file
        return self.state_dir / "agent_client_key"

    @property
    def resolved_agent_trusted_ca_file(self) -> Path:
        # The node CA by default, and not a separate file: an agent's server
        # certificate is issued by that authority, so anything else here
        # would mean the control plane refusing every node it enrolled.
        if self.agent_trusted_ca_file is not None:
            return self.agent_trusted_ca_file
        return self.resolved_node_ca_certificate_file

    agent_request_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    reconciliation_batch_size: int = Field(default=500, ge=1, le=5_000)

    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3_600)
    refresh_token_ttl_days: int = Field(default=30, ge=1, le=90)
    password_reset_ttl_minutes: int = Field(default=30, ge=5, le=120)
    activation_token_ttl_hours: int = Field(default=24, ge=1, le=168)
    account_request_ttl_days: int = Field(default=7, ge=1, le=90)
    default_device_limit: int = Field(default=3, ge=1, le=20)
    admin_session_ttl_minutes: int = Field(default=30, ge=5, le=480)
    admin_session_absolute_ttl_hours: int = Field(default=8, ge=1, le=24)
    admin_preauth_ttl_minutes: int = Field(default=5, ge=1, le=15)
    admin_step_up_ttl_minutes: int = Field(default=5, ge=1, le=15)
    totp_allowed_skew_steps: int = Field(default=1, ge=0, le=1)

    auth_rate_window_seconds: int = Field(default=900, ge=60, le=3_600)
    user_login_rate_limit: int = Field(default=10, ge=1, le=100)
    # Per /24 for sign-in and password reset, apart from the per-account
    # limit above: everyone on one mobile carrier's NAT, or connected through
    # one VPN server (the app's API calls use the tunnel), shares a network.
    user_network_rate_limit: int = Field(default=100, ge=1, le=10_000)
    admin_login_rate_limit: int = Field(default=5, ge=1, le=50)
    admin_mfa_rate_limit: int = Field(default=5, ge=1, le=50)
    password_reset_rate_limit: int = Field(default=5, ge=1, le=50)
    account_request_rate_limit: int = Field(default=5, ge=1, le=50)
    account_request_review_rate_limit: int = Field(default=20, ge=1, le=100)
    # High enough that normal VPN on/off toggling never trips it -- this
    # bucket also covers disconnect, so a user reconnecting several times in
    # a session is expected usage, not abuse. The 100 ceiling itself (the
    # Field bound below) is what actually backstops a runaway client retry
    # loop; 10 was tuned for a login-style rate limit, not a toggle button.
    device_provision_rate_limit: int = Field(default=100, ge=1, le=100)
    admin_lockout_threshold: int = Field(default=5, ge=2, le=20)
    admin_lockout_seconds: int = Field(default=900, ge=60, le=86_400)

    @field_validator(
        "agent_client_cert_file", "agent_client_key_file", "agent_trusted_ca_file", mode="before"
    )
    @classmethod
    def _empty_path_is_unset(cls, value: object) -> object:
        # Compose cannot leave a variable out, only pass it empty. Empty means
        # "issue it into state_dir", which a fresh install needs: the secrets
        # directory is mounted read-only (2026-10-26, first install on a new host).
        return None if value == "" else value

    @field_validator("xray_client_dns")
    @classmethod
    def _client_dns_shape(cls, value: str) -> str:
        value = value.strip()
        if value:
            try:
                if ip_address(value).version != 4:
                    raise ValueError
            except ValueError:
                raise ValueError("expected an IPv4 address such as 198.18.0.53") from None
        return value

    @field_validator("client_latest_version")
    @classmethod
    def _client_version_shape(cls, value: str) -> str:
        value = value.strip().removeprefix("v")
        if value and not re.fullmatch(r"\d+(\.\d+){1,3}", value):
            raise ValueError("expected a version such as 0.1.24")
        return value

    @field_validator("api_public_url", "admin_public_url")
    @classmethod
    def validate_public_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("must not contain credentials, query parameters, or fragments")
        return value.rstrip("/")

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr) -> SecretStr:
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise ValueError("must be an absolute Redis URL")
        if parsed.fragment:
            raise ValueError("must not contain a fragment")
        return value

    @field_validator("xray_xhttp_path")
    @classmethod
    def validate_xray_xhttp_path(cls, value: str) -> str:
        if not _XHTTP_PATH_PATTERN.fullmatch(value):
            raise ValueError("must be an absolute path of safe characters")
        return value

    @field_validator("jwt_issuer", "jwt_audience")
    @classmethod
    def validate_jwt_context(cls, value: str) -> str:
        if value.strip() != value:
            raise ValueError("must not contain leading or trailing whitespace")
        return value

    @field_validator("allowed_origins")
    @classmethod
    def validate_allowed_origins(cls, value: str) -> str:
        origins = [origin.strip() for origin in value.split(",")]
        if not origins or any(not origin for origin in origins):
            raise ValueError("must contain at least one exact origin")
        for origin in origins:
            parsed = urlsplit(origin)
            if origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("must contain only exact HTTP(S) origins")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("origins must not contain paths, queries, or fragments")
        return ",".join(origins)

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        try:
            url = make_url(value.get_secret_value())
        except ArgumentError as exc:
            raise ValueError("must be a valid SQLAlchemy PostgreSQL URL") from exc
        if url.drivername != "postgresql+psycopg":
            raise ValueError("must use the postgresql+psycopg driver")
        if not url.database or not url.username:
            raise ValueError("must identify a database and least-privilege role")
        if url.query:
            raise ValueError("must not contain query parameters")
        return value

    @model_validator(mode="after")
    def validate_runtime_boundaries(self) -> Self:
        if self.admin_session_ttl_minutes > self.admin_session_absolute_ttl_hours * 60:
            raise ValueError("administrator idle session lifetime cannot exceed absolute lifetime")
        if self.env != "production":
            return self
        urls = [self.api_public_url, self.admin_public_url, *self.allowed_origins.split(",")]
        for url in urls:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError(
                    "production URLs and origins must use HTTPS and non-loopback hosts"
                )
        if self.migration_database_url is not None and (
            self.migration_database_url.get_secret_value() == self.database_url.get_secret_value()
        ):
            raise ValueError("production application and migration database roles must differ")
        required_secret_files = {
            "jwt_private_key_file": self.jwt_private_key_file,
            "jwt_public_key_file": self.jwt_public_key_file,
            "token_pepper_file": self.token_pepper_file,
            "mfa_encryption_key_file": self.mfa_encryption_key_file,
            # Required for the same reason as the MFA key above: without it
            # key_material.py falls back to a per-process ephemeral key, and
            # an Xray credential encrypted under one is unrecoverable after
            # any restart -- see that module's _load_xray_encryption_keys.
            "xray_encryption_key_file": self.xray_encryption_key_file,
        }
        missing = [name for name, path in required_secret_files.items() if path is None]
        if missing:
            raise ValueError("production authentication secret files are required")
        optional_secret_paths = {
            "jwt_previous_public_keys_dir": self.jwt_previous_public_keys_dir,
            "token_previous_peppers_dir": self.token_previous_peppers_dir,
            "mfa_previous_encryption_keys_dir": self.mfa_previous_encryption_keys_dir,
            "xray_previous_encryption_keys_dir": self.xray_previous_encryption_keys_dir,
        }
        if any(
            path is not None and not path.is_absolute()
            for path in (*required_secret_files.values(), *optional_secret_paths.values())
        ):
            raise ValueError("production authentication secret file paths must be absolute")
        parsed_redis = urlsplit(self.redis_url.get_secret_value())
        if not parsed_redis.password:
            raise ValueError("production Redis must use authentication")
        return self

    @property
    def allowed_origin_values(self) -> tuple[str, ...]:
        """Return the exact CORS/origin allowlist without reparsing at call sites."""

        return tuple(self.allowed_origins.split(","))

    @property
    def admin_cookie_name(self) -> str:
        """Use the host-only cookie prefix whenever HTTPS is mandatory."""

        return "__Host-nebula_admin" if self.env in {"staging", "production"} else "nebula_admin"

    @property
    def admin_cookie_secure(self) -> bool:
        """Permit local HTTP development while requiring secure deployed cookies."""

        return self.env in {"staging", "production"}

    @property
    def admin_csrf_cookie_name(self) -> str:
        """Name the readable, host-only CSRF cookie separately from the session."""

        return "__Host-nebula_csrf" if self.admin_cookie_secure else "nebula_csrf"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
