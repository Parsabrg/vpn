"""In-memory WireGuard driver: no subprocess calls, no NET_ADMIN capability
required. This is the "capability-free mock agent" the Compose vpn-agent:
service runs by default, and what unit tests inject via create_app().
"""

import base64
from datetime import UTC, datetime

from nebula_agent import __version__
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
from nebula_agent.drivers.config_store import ConfigStore, DesiredInterfaceState, RenderedPeer
from nebula_agent.drivers.errors import ApplyError

# Fixture-only placeholder, not a real WireGuard key.
_DEFAULT_SERVER_PUBLIC_KEY = base64.b64encode(bytes([7] * 32)).decode()


class FakeWireGuardRunner:
    """Satisfies the WireGuardDriver Protocol structurally (see drivers/base.py)."""

    def __init__(
        self,
        *,
        config_store: ConfigStore | None = None,
        server_public_key: str = _DEFAULT_SERVER_PUBLIC_KEY,
        listen_port: int = 51820,
        public_endpoint: str = "vpn.test:51820",
        client_dns: str = "1.1.1.1",
        client_allowed_ips: str = "0.0.0.0/0,::/0",
        persistent_keepalive_seconds: int = 25,
    ) -> None:
        self._config_store = config_store
        self._state = (
            config_store.read_last_known_good()
            if config_store is not None
            else DesiredInterfaceState()
        )
        self._server_public_key = server_public_key
        self._listen_port = listen_port
        self._public_endpoint = public_endpoint
        self._client_dns = client_dns
        self._client_allowed_ips = client_allowed_ips
        self._persistent_keepalive_seconds = persistent_keepalive_seconds
        self._generation = 0
        self._fail_next = False

    def fail_next_apply(self) -> None:
        """Test-only hook: the next mutating call raises ApplyError instead
        of applying, exercising the failure/rollback response path without a
        real subprocess."""

        self._fail_next = True

    def _apply(self, new_state: DesiredInterfaceState) -> int:
        if self._fail_next:
            self._fail_next = False
            raise ApplyError("simulated apply failure")
        self._generation += 1
        self._state = new_state
        if self._config_store is not None:
            text = self._config_store.render_candidate(new_state)
            candidate = self._config_store.write_candidate_atomically(text)
            self._config_store.promote_candidate_to_last_known_good(candidate)
        return self._generation

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        peer = RenderedPeer(
            public_key=request.public_key,
            assigned_address=request.assigned_address,
            persistent_keepalive_seconds=request.persistent_keepalive_seconds,
        )
        common = {
            "server_public_key": self._server_public_key,
            "listen_port": self._listen_port,
            "public_endpoint": self._public_endpoint,
            "client_dns": self._client_dns,
            "client_allowed_ips": self._client_allowed_ips,
            "persistent_keepalive_seconds": self._persistent_keepalive_seconds,
        }
        try:
            generation = self._apply(self._state.with_peer(peer))
        except ApplyError:
            return ProvisionDeviceResponse(
                state="failed",
                applied_generation=self._generation,
                error_code="apply_failed",
                **common,
            )
        return ProvisionDeviceResponse(state="active", applied_generation=generation, **common)

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        try:
            generation = self._apply(self._state.without_peer(request.public_key))
        except ApplyError:
            return RevokeDeviceResponse(
                state="failed",
                applied_generation=self._generation,
                revoked_at=datetime.now(UTC),
                error_code="apply_failed",
            )
        return RevokeDeviceResponse(
            state="revoked", applied_generation=generation, revoked_at=datetime.now(UTC)
        )

    async def enable_device(self, request: EnableDeviceRequest) -> EnableDeviceResponse:
        peer = RenderedPeer(
            public_key=request.public_key,
            assigned_address=request.assigned_address,
        )
        try:
            generation = self._apply(self._state.with_peer(peer))
        except ApplyError:
            return EnableDeviceResponse(
                state="failed", applied_generation=self._generation, error_code="apply_failed"
            )
        return EnableDeviceResponse(state="enabled", applied_generation=generation)

    async def disable_device(self, request: DisableDeviceRequest) -> DisableDeviceResponse:
        try:
            generation = self._apply(self._state.without_peer(request.public_key))
        except ApplyError:
            return DisableDeviceResponse(
                state="failed", applied_generation=self._generation, error_code="apply_failed"
            )
        return DisableDeviceResponse(state="disabled", applied_generation=generation)

    async def health(self, request: HealthRequest) -> HealthResponse:
        return HealthResponse(
            state="healthy",
            observed_at=datetime.now(UTC),
            agent_version=__version__,
            interface_up=True,
            peer_count=len(self._state.peers),
        )

    async def reconcile(self, request: ReconcileRequest) -> ReconcileResponse:
        match = self._state.peer(request.public_key)
        if match is None:
            return ReconcileResponse(outcome="drift_detected", observed_generation=None)
        if match.assigned_address != request.assigned_address:
            return ReconcileResponse(outcome="ambiguous", observed_generation=self._generation)
        return ReconcileResponse(outcome="in_sync", observed_generation=self._generation)
