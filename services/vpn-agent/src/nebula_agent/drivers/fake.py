"""In-memory WireGuard and Xray drivers: no subprocess calls, no NET_ADMIN
capability required. These are the "capability-free mock agent" the Compose
vpn-agent: service runs by default, and what unit tests inject via
create_app().
"""

import base64
from datetime import UTC, datetime
from uuid import UUID

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
from nebula_agent.drivers.errors import ApplyError, ValidationError
from nebula_agent.drivers.xray_base import (
    ProvisionXrayClientRequest,
    ProvisionXrayClientResponse,
    PruneXrayClientsRequest,
    PruneXrayClientsResponse,
    ReconcileXrayClientRequest,
    ReconcileXrayClientResponse,
    RevokeXrayClientRequest,
    RevokeXrayClientResponse,
    XrayHealthRequest,
    XrayHealthResponse,
)
from nebula_agent.drivers.xray_config_store import (
    DesiredXrayState,
    RenderedXrayClient,
    XrayInboundProfile,
)

_DEFAULT_FAKE_XRAY_PROFILE = XrayInboundProfile(
    protocol_profile_code="vless-xhttp-tls",
    transport="xhttp",
    listen="127.0.0.1",
    port=8446,
    security="none",
    xhttp_path="/xhttp",
)

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
        self._fail_next = False

    def fail_next_apply(self) -> None:
        """Test-only hook: the next mutating call raises ApplyError instead
        of applying, exercising the failure/rollback response path without a
        real subprocess."""

        self._fail_next = True

    def _last_applied_generation(self, public_key: str) -> int:
        """What a failed apply reports: the peer's own last-applied
        generation (0 if it was never successfully applied), never a global
        counter -- two peers can legitimately be at different generations."""

        previous = self._state.peer(public_key)
        return 0 if previous is None else previous.generation

    def _apply(self, new_state: DesiredInterfaceState) -> None:
        if self._fail_next:
            self._fail_next = False
            raise ApplyError("simulated apply failure")
        self._state = new_state
        if self._config_store is not None:
            text = self._config_store.render_candidate(new_state)
            candidate = self._config_store.write_candidate_atomically(text)
            self._config_store.promote_candidate_to_last_known_good(candidate)

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        peer = RenderedPeer(
            public_key=request.public_key,
            assigned_address=request.assigned_address,
            persistent_keepalive_seconds=request.persistent_keepalive_seconds,
            generation=request.desired_generation,
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
            self._apply(self._state.with_peer(peer))
        except ApplyError:
            return ProvisionDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(request.public_key),
                error_code="apply_failed",
                **common,
            )
        return ProvisionDeviceResponse(
            state="active", applied_generation=request.desired_generation, **common
        )

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        try:
            self._apply(self._state.without_peer(request.public_key))
        except ApplyError:
            return RevokeDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(request.public_key),
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
        try:
            self._apply(self._state.with_peer(peer))
        except ApplyError:
            return EnableDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(request.public_key),
                error_code="apply_failed",
            )
        return EnableDeviceResponse(state="enabled", applied_generation=request.desired_generation)

    async def disable_device(self, request: DisableDeviceRequest) -> DisableDeviceResponse:
        try:
            self._apply(self._state.without_peer(request.public_key))
        except ApplyError:
            return DisableDeviceResponse(
                state="failed",
                applied_generation=self._last_applied_generation(request.public_key),
                error_code="apply_failed",
            )
        return DisableDeviceResponse(
            state="disabled", applied_generation=request.desired_generation
        )

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
            return ReconcileResponse(outcome="ambiguous", observed_generation=match.generation)
        return ReconcileResponse(outcome="in_sync", observed_generation=match.generation)


class FakeXrayRunner:
    """Satisfies the XrayDriver Protocol structurally (see drivers/xray_base.py)."""

    def __init__(
        self,
        *,
        server_address: str = "vpn.test",
        sni: str = "vpn.test",
        profiles: tuple[XrayInboundProfile, ...] = (_DEFAULT_FAKE_XRAY_PROFILE,),
    ) -> None:
        self._state = DesiredXrayState()
        self._server_address = server_address
        self._sni = sni
        self._profiles = profiles
        self._fail_next = False

    def fail_next_apply(self) -> None:
        """Test-only hook: the next mutating call raises ApplyError instead
        of applying, exercising the failure response path without a real
        subprocess."""

        self._fail_next = True

    def _profile_for(self, protocol_profile_code: str) -> XrayInboundProfile:
        for profile in self._profiles:
            if profile.protocol_profile_code == protocol_profile_code:
                return profile
        raise ValidationError(f"no configured Xray inbound for profile {protocol_profile_code!r}")

    def _last_applied_generation(self, client_uuid: UUID) -> int:
        previous = self._state.client(client_uuid)
        return 0 if previous is None else previous.generation

    def _apply(self, new_state: DesiredXrayState) -> None:
        if self._fail_next:
            self._fail_next = False
            raise ApplyError("simulated apply failure")
        self._state = new_state

    def _response_common(self, profile: XrayInboundProfile) -> dict[str, object]:
        return {
            "server_address": self._server_address,
            "sni": self._sni,
            "port": profile.port,
            "transport": profile.transport,
            "transport_security": profile.security,
            "path": profile.xhttp_path or profile.ws_path,
            "service_name": profile.grpc_service_name,
        }

    async def provision_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        profile = self._profile_for(request.protocol_profile_code)
        client = RenderedXrayClient(
            client_uuid=request.client_uuid,
            protocol_profile_code=request.protocol_profile_code,
            generation=request.desired_generation,
        )
        common = self._response_common(profile)
        try:
            self._apply(self._state.with_client(client))
        except ApplyError:
            return ProvisionXrayClientResponse(
                state="failed",
                applied_generation=self._last_applied_generation(request.client_uuid),
                error_code="apply_failed",
                **common,
            )
        return ProvisionXrayClientResponse(
            state="active", applied_generation=request.desired_generation, **common
        )

    async def revoke_client(self, request: RevokeXrayClientRequest) -> RevokeXrayClientResponse:
        self._profile_for(request.protocol_profile_code)
        try:
            self._apply(self._state.without_client(request.client_uuid))
        except ApplyError:
            return RevokeXrayClientResponse(
                state="failed",
                applied_generation=self._last_applied_generation(request.client_uuid),
                revoked_at=datetime.now(UTC),
                error_code="apply_failed",
            )
        return RevokeXrayClientResponse(
            state="revoked",
            applied_generation=request.desired_generation,
            revoked_at=datetime.now(UTC),
        )

    async def prune_clients(self, request: PruneXrayClientsRequest) -> PruneXrayClientsResponse:
        keep = {expected.client_uuid for expected in request.expected}
        survivors = tuple(c for c in self._state.clients if c.client_uuid in keep)
        removed = len(self._state.clients) - len(survivors)
        if removed == 0:
            return PruneXrayClientsResponse(state="pruned", removed=0, kept=len(survivors))
        try:
            self._apply(DesiredXrayState(clients=survivors))
        except ApplyError:
            return PruneXrayClientsResponse(
                state="failed", removed=0, kept=len(self._state.clients), error_code="apply_failed"
            )
        return PruneXrayClientsResponse(state="pruned", removed=removed, kept=len(survivors))

    async def reconcile_client(
        self, request: ReconcileXrayClientRequest
    ) -> ReconcileXrayClientResponse:
        """The fake keeps only one view of the world, so it can never surface
        the config-vs-bookkeeping disagreement the native driver reports as
        ambiguous -- it answers present/absent and nothing else."""

        try:
            self._profile_for(request.protocol_profile_code)
        except ValidationError:
            return ReconcileXrayClientResponse(outcome="ambiguous", observed_generation=None)
        recorded = self._state.client(request.client_uuid)
        if recorded is None:
            return ReconcileXrayClientResponse(outcome="drift_detected", observed_generation=None)
        if recorded.protocol_profile_code != request.protocol_profile_code:
            return ReconcileXrayClientResponse(
                outcome="ambiguous", observed_generation=recorded.generation
            )
        return ReconcileXrayClientResponse(
            outcome="in_sync", observed_generation=recorded.generation
        )

    async def health(self, request: XrayHealthRequest) -> XrayHealthResponse:
        return XrayHealthResponse(
            state="healthy",
            observed_at=datetime.now(UTC),
            agent_version=__version__,
            listener_up=True,
            client_count=len(self._state.clients),
        )

    async def resync_served_config(self) -> bool:
        """Nothing here is served from a config file, so there is nothing to
        bring up to date -- False for the same reason the native driver
        returns it when the served config already matches."""

        return False

    def authorize_hysteria(self, auth: str) -> str | None:
        """No Hysteria2 is served here, so nobody is admitted to it."""

        return None
