"""Real WireGuardDriver: fixed `wg`/`wg-quick` subprocess calls, never a shell.

`ip` is deliberately not used here -- interface creation (`ip link add wg0
type wireguard`) is one-time host provisioning (systemd ExecStartPre /
`wg-quick up`), not something this driver does per-request. This keeps the
driver's own subprocess surface to exactly wg/wg-quick, both fixed absolute
paths read from Settings, never derived from request data.
"""

from datetime import UTC, datetime
from pathlib import Path

import anyio

from nebula_agent import __version__
from nebula_agent.drivers._exec import run_fixed_argv
from nebula_agent.drivers.base import (
    DisableDeviceRequest,
    DisableDeviceResponse,
    EnableDeviceRequest,
    EnableDeviceResponse,
    HealthRequest,
    HealthResponse,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ReconcileRequest,
    ReconcileResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
)
from nebula_agent.drivers.config_store import (
    ConfigStore,
    DesiredInterfaceState,
    IPAddress,
    RenderedPeer,
)
from nebula_agent.drivers.errors import ApplyError, RollbackFailedError, ValidationError
from nebula_agent.settings import Settings

_PUBKEY_TIMEOUT_SECONDS = 5.0
_STRIP_TIMEOUT_SECONDS = 5.0
_SYNCCONF_TIMEOUT_SECONDS = 15.0
_SHOW_TIMEOUT_SECONDS = 5.0


def build_pubkey_argv(settings: Settings) -> list[str]:
    return [str(settings.wg_binary), "pubkey"]


def build_strip_argv(settings: Settings, candidate: Path) -> list[str]:
    return [str(settings.wg_quick_binary), "strip", str(candidate)]


def build_syncconf_argv(settings: Settings, candidate: Path) -> list[str]:
    return [str(settings.wg_binary), "syncconf", settings.wg_interface, str(candidate)]


def build_show_dump_argv(settings: Settings) -> list[str]:
    return [str(settings.wg_binary), "show", settings.wg_interface, "dump"]


def validate_address_in_client_pool(settings: Settings, peer: RenderedPeer) -> None:
    """Protocol-specific validation the driver owns (docs/architecture.md):
    the assigned address must fall inside the server's configured client
    pool, beyond what the DB's masklen-only CHECK constraint enforces."""

    if peer.assigned_address not in settings.wg_client_pool:
        raise ValidationError("assigned_address is outside wg_client_pool")


def parse_show_dump(output: str) -> dict[str, str]:
    """Maps public_key -> allowed_ips from `wg show <interface> dump` output.
    The first line (interface identity: private-key/public-key/listen-port/
    fwmark) is skipped; only rows shaped like a peer line (4+ tab-separated
    fields) are kept."""

    peers: dict[str, str] = {}
    lines = output.strip("\n").split("\n")
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        public_key, _preshared_key, _endpoint, allowed_ips = fields[:4]
        peers[public_key] = allowed_ips
    return peers


def expected_allowed_ips(address: IPAddress) -> str:
    return f"{address}/32" if address.version == 4 else f"{address}/128"


class NativeWireGuardDriver:
    """Satisfies the WireGuardDriver Protocol (see drivers/base.py) against a
    real WireGuard interface that already exists on the host."""

    def __init__(self, settings: Settings, config_store: ConfigStore) -> None:
        self._settings = settings
        self._config_store = config_store
        self._server_public_key: str | None = None

    async def _server_pubkey(self) -> str:
        if self._server_public_key is None:
            private_key_path = anyio.Path(str(self._settings.wg_server_private_key_file))
            private_key_bytes = await private_key_path.read_bytes()
            result = await run_fixed_argv(
                build_pubkey_argv(self._settings),
                timeout_seconds=_PUBKEY_TIMEOUT_SECONDS,
                stdin=private_key_bytes,
            )
            if result.returncode != 0:
                raise ApplyError("failed to derive the server public key")
            self._server_public_key = result.stdout.decode().strip()
        return self._server_public_key

    def _last_applied_generation(self, current: DesiredInterfaceState, public_key: str) -> int:
        """What a failed apply reports: the peer's own last-known-good
        generation (0 if it was never successfully applied) -- never a
        global counter, since peers are independently provisioned."""

        previous = current.peer(public_key)
        return 0 if previous is None else previous.generation

    async def _rollback(self) -> None:
        candidate = self._config_store.write_candidate_atomically(
            self._config_store.rollback_text()
        )
        result = await run_fixed_argv(
            build_syncconf_argv(self._settings, candidate),
            timeout_seconds=_SYNCCONF_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            raise RollbackFailedError(result.stderr.decode(errors="replace").strip())

    async def _apply_delta(self, desired: DesiredInterfaceState) -> None:
        """Render, validate, and apply -- on any failure past validation,
        roll back to the last-known-good state before surfacing the error, so
        the interface never sits at an unvalidated or half-applied config."""

        text = self._config_store.render_candidate(desired)
        candidate = self._config_store.write_candidate_atomically(text)

        validation = await run_fixed_argv(
            build_strip_argv(self._settings, candidate),
            timeout_seconds=_STRIP_TIMEOUT_SECONDS,
        )
        if validation.returncode != 0:
            raise ValidationError(validation.stderr.decode(errors="replace").strip())

        apply_result = await run_fixed_argv(
            build_syncconf_argv(self._settings, candidate),
            timeout_seconds=_SYNCCONF_TIMEOUT_SECONDS,
        )
        if apply_result.returncode != 0:
            await self._rollback()
            raise ApplyError(apply_result.stderr.decode(errors="replace").strip())

        self._config_store.promote_candidate_to_last_known_good(candidate)

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        peer = RenderedPeer(
            public_key=request.public_key,
            assigned_address=request.assigned_address,
            persistent_keepalive_seconds=request.persistent_keepalive_seconds,
            generation=request.desired_generation,
        )
        validate_address_in_client_pool(self._settings, peer)
        current = self._config_store.read_last_known_good()

        common = {
            "server_public_key": await self._server_pubkey(),
            "listen_port": self._settings.wg_listen_port,
            "public_endpoint": self._settings.wg_public_endpoint,
            "client_dns": str(self._settings.wg_client_dns),
            "client_allowed_ips": self._settings.wg_client_allowed_ips,
            "persistent_keepalive_seconds": self._settings.wg_persistent_keepalive_seconds,
        }
        try:
            await self._apply_delta(current.with_peer(peer))
        except (ValidationError, ApplyError):
            return ProvisionDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(current, request.public_key),
                error_code="apply_failed",
                **common,
            )
        return ProvisionDeviceResponse(
            state="active",
            applied_generation=request.desired_generation,
            **common,
        )

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        current = self._config_store.read_last_known_good()
        try:
            await self._apply_delta(current.without_peer(request.public_key))
        except (ValidationError, ApplyError):
            return RevokeDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(current, request.public_key),
                revoked_at=datetime.now(UTC),
                error_code="apply_failed",
            )
        return RevokeDeviceResponse(
            state="revoked",
            applied_generation=request.desired_generation,
            revoked_at=datetime.now(UTC),
        )

    async def enable_device(self, request: EnableDeviceRequest) -> EnableDeviceResponse:
        peer = RenderedPeer(
            public_key=request.public_key,
            assigned_address=request.assigned_address,
            generation=request.desired_generation,
        )
        validate_address_in_client_pool(self._settings, peer)
        current = self._config_store.read_last_known_good()
        try:
            await self._apply_delta(current.with_peer(peer))
        except (ValidationError, ApplyError):
            return EnableDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(current, request.public_key),
                error_code="apply_failed",
            )
        return EnableDeviceResponse(state="enabled", applied_generation=request.desired_generation)

    async def disable_device(self, request: DisableDeviceRequest) -> DisableDeviceResponse:
        current = self._config_store.read_last_known_good()
        try:
            await self._apply_delta(current.without_peer(request.public_key))
        except (ValidationError, ApplyError):
            return DisableDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(current, request.public_key),
                error_code="apply_failed",
            )
        return DisableDeviceResponse(
            state="disabled", applied_generation=request.desired_generation
        )

    async def health(self, request: HealthRequest) -> HealthResponse:
        result = await run_fixed_argv(
            build_show_dump_argv(self._settings), timeout_seconds=_SHOW_TIMEOUT_SECONDS
        )
        if result.returncode != 0:
            return HealthResponse(
                state="unreachable",
                observed_at=datetime.now(UTC),
                agent_version=__version__,
                interface_up=False,
                peer_count=0,
                error_code="show_failed",
            )
        peers = parse_show_dump(result.stdout.decode(errors="replace"))
        return HealthResponse(
            state="healthy",
            observed_at=datetime.now(UTC),
            agent_version=__version__,
            interface_up=True,
            peer_count=len(peers),
        )

    async def reconcile(self, request: ReconcileRequest) -> ReconcileResponse:
        """Compares two independent views: the live kernel peer table (via
        `wg show dump`, which knows nothing about generations) and this
        driver's own last-known-good record (which does) -- both must agree
        with the request for an in_sync outcome."""

        result = await run_fixed_argv(
            build_show_dump_argv(self._settings), timeout_seconds=_SHOW_TIMEOUT_SECONDS
        )
        if result.returncode != 0:
            return ReconcileResponse(
                outcome="ambiguous", observed_generation=None, error_code="show_failed"
            )

        live_peers = parse_show_dump(result.stdout.decode(errors="replace"))
        live_allowed_ips = live_peers.get(request.public_key)
        recorded = self._config_store.read_last_known_good().peer(request.public_key)

        if live_allowed_ips is None or recorded is None:
            return ReconcileResponse(outcome="drift_detected", observed_generation=None)

        address_matches = (
            live_allowed_ips == expected_allowed_ips(request.assigned_address)
            and recorded.assigned_address == request.assigned_address
        )
        if not address_matches:
            return ReconcileResponse(outcome="ambiguous", observed_generation=recorded.generation)

        return ReconcileResponse(outcome="in_sync", observed_generation=recorded.generation)
