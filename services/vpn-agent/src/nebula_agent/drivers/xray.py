"""Real XrayDriver: renders every configured inbound (see settings.py's
build_xray_inbound_profiles) into one Xray config file and applies it via
systemd, mirroring drivers/wireguard.py's render-full-state -> validate ->
apply -> rollback-on-failure shape. Xray has no `wg syncconf`-style
incremental apply, so every change is validated with `xray run -test`
against the candidate file before it is ever written to the path Xray
itself reads.

Apply uses `systemctl restart nebula-xray`, not `reload`/`reload-or-restart`:
Xray-core has no SIGHUP-based hot config reload (confirmed against a real
deployment -- sending it SIGHUP just kills the process outright, since it
installs no handler for it and the OS default action for SIGHUP is
termination), so `ExecReload=` sending SIGHUP doesn't reload anything, it
silently takes the service down, which surfaced as every single
connect/disconnect flapping the tunnel. `restart` always fully replaces the
process with the newly rendered config; it also covers a fresh host's very
first provision (config.json written while the unit is still inactive --
`restart` on an inactive unit behaves like a plain `start`, unlike `reload`,
which only ever signals an already-running process and fails outright
against one that was never started).

A restart drops every *other* connected client, on every inbound, each time
any one client changes -- which on a server people use is every connect and
every disconnect. So with `xray_live_client_updates` on, a change that only
adds or removes clients goes through Xray's own API instead (`xray api adu` /
`rmu`), and the process keeps running. The config file is still written
first, so a later restart loads the same set; anything beyond the client
lists, or any API step that does not check out, falls back to the restart.

Removing a client through the API refuses its new connections but leaves open
ones running -- measured: a download carried on after `rmu` until it finished.
A revoke has to actually cut someone off, so a removed client's counters are
watched for a while, and if they still move, Xray is restarted after all. See
_watch_for_lingering.

This driver's subprocess surface stays exactly `xray`/`systemctl`, both
fixed absolute paths, never a shell.
"""

import asyncio
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from nebula_agent import __version__
from nebula_agent.drivers._exec import run_fixed_argv
from nebula_agent.drivers.errors import ApplyError, RollbackFailedError, ValidationError
from nebula_agent.drivers.hysteria_config_store import (
    HYSTERIA_AUTH_PATH,
    HYSTERIA_AUTH_PORT,
    NO_CLIENTS_USER,
    TRAFFIC_STATS_PORT,
    HysteriaServerProfile,
    render_hysteria_server_config,
    traffic_stats_secret,
)
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
    SS2022_METHOD,
    STATS_API_PORT,
    DesiredXrayState,
    RenderedXrayClient,
    XrayConfigStore,
    XrayInboundProfile,
    client_email,
    render_xray_server_config,
    ss2022_user_key,
    uuid_from_ss2022_key,
)
from nebula_agent.settings import Settings, parse_dns_redirect

_LOGGER = logging.getLogger(__name__)

_HEALTH_TIMEOUT_SECONDS = 5.0
_SYSTEMCTL_BINARY = "/usr/bin/systemctl"
_XRAY_UNIT = "nebula-xray"
_HYSTERIA_UNIT = "nebula-hysteria"
# Long enough to cover a normal restart, short enough that a genuinely broken
# config still fails the apply rather than hanging the caller.
_HYSTERIA_ACTIVE_TIMEOUT_SECONDS = 15.0
_HYSTERIA_ACTIVE_POLL_SECONDS = 0.5
_XRAY_API_TIMEOUT_SECONDS = 10.0
# How long a removed client is watched for connections that outlived it.
# Longer than Xray's default connIdle of 300 seconds: a connection that stays
# quiet that long is closed by Xray itself, so one that is still open after
# this has carried traffic, and was seen doing it.
_LINGER_WATCH_SECONDS = 330.0
_LINGER_POLL_SECONDS = 10.0


@dataclass(slots=True)
class _Lingering:
    """A client removed through the API, and what its counters said."""

    removed_at: float
    baseline: int | None = None


def build_validate_argv(settings: Settings, candidate: Path) -> list[str]:
    return [str(settings.xray_binary), "run", "-test", "-config", str(candidate)]


def build_reload_argv() -> list[str]:
    return [_SYSTEMCTL_BINARY, "restart", _XRAY_UNIT]


def build_hysteria_reload_argv() -> list[str]:
    return [_SYSTEMCTL_BINARY, "restart", _HYSTERIA_UNIT]


def build_hysteria_is_active_argv() -> list[str]:
    return [_SYSTEMCTL_BINARY, "is-active", _HYSTERIA_UNIT]


class NativeXrayDriver:
    """Satisfies the XrayDriver Protocol (see drivers/xray_base.py) against a
    real Xray process managed by the `nebula-xray` systemd unit."""

    def __init__(
        self,
        settings: Settings,
        config_store: XrayConfigStore,
        profiles: tuple[XrayInboundProfile, ...] | None = None,
        hysteria_profile: HysteriaServerProfile | None = None,
    ) -> None:
        self._settings = settings
        self._config_store = config_store
        self._profiles = (
            profiles if profiles is not None else settings.build_xray_inbound_profiles()
        )
        # Hysteria2 is served by a different binary in a different unit, so
        # it is not one of the Xray inbounds above -- but its clients share
        # the same provisioning flow and the same bookkeeping, so this
        # driver applies to both.
        self._hysteria_profile = (
            hysteria_profile if hysteria_profile is not None else settings.hysteria_server_profile()
        )
        # Every change reads the recorded client set, changes it and writes it
        # back, with awaits in between. Two at once -- two people connecting
        # in the same second -- would each write a set missing the other's
        # client. One at a time.
        self._apply_lock = asyncio.Lock()
        # Keyed by client email: removed live, and not yet known to be gone.
        self._lingering: dict[str, _Lingering] = {}
        self._linger_task: asyncio.Task[None] | None = None

    def _serves(self, protocol_profile_code: str) -> bool:
        if (
            self._hysteria_profile is not None
            and self._hysteria_profile.protocol_profile_code == protocol_profile_code
        ):
            return True
        return any(p.protocol_profile_code == protocol_profile_code for p in self._profiles)

    def _profile_for(self, protocol_profile_code: str) -> XrayInboundProfile:
        for profile in self._profiles:
            if profile.protocol_profile_code == protocol_profile_code:
                return profile
        # The API requested a profile this agent was never configured to
        # serve -- a deployment-consistency bug (the two sides' profile
        # sets disagree), not a normal client-facing failure, so this
        # propagates uncaught to main.py's DriverError handler (500) rather
        # than being reported as an ordinary "failed" response.
        raise ValidationError(f"no configured Xray inbound for profile {protocol_profile_code!r}")

    def _last_applied_generation(self, current: DesiredXrayState, client_uuid: UUID) -> int:
        """What a failed apply reports: the client's own last-known-good
        generation (0 if it was never successfully applied) -- never a
        global counter, mirroring NativeWireGuardDriver's same choice."""

        previous = current.client(client_uuid)
        return 0 if previous is None else previous.generation

    def _render(self, desired: DesiredXrayState) -> str:
        tls_cert = self._settings.xray_tls_cert_file
        tls_key = self._settings.xray_tls_key_file
        return render_xray_server_config(
            desired,
            self._profiles,
            tls_cert_file=str(tls_cert) if tls_cert is not None else None,
            tls_key_file=str(tls_key) if tls_key is not None else None,
            api_host=self._settings.xray_api_host,
            live_client_updates=self._settings.xray_live_client_updates,
            dns_redirect=parse_dns_redirect(self._settings.xray_dns_redirect),
        )

    async def _validate(self, server_config_text: str) -> None:
        """Validate against the store's own scratch copy -- never against the
        real config path, so a failed validation never disturbs whatever
        Xray currently has loaded."""

        validate_target = self._config_store.write_validate_scratch_atomically(server_config_text)
        result = await run_fixed_argv(
            build_validate_argv(self._settings, validate_target),
            timeout_seconds=self._settings.xray_validate_timeout_seconds,
        )
        if result.returncode != 0:
            raise ValidationError(result.stderr.decode(errors="replace").strip())

    async def _reload(self) -> None:
        result = await run_fixed_argv(
            build_reload_argv(), timeout_seconds=self._settings.xray_apply_timeout_seconds
        )
        if result.returncode != 0:
            raise ApplyError(result.stderr.decode(errors="replace").strip())

    def _xray_config_matches(self, rendered: str) -> bool:
        """Whether the served Xray config is already what we would write.

        Mirrors `_hysteria_config_matches`, and for the same reason: one small
        local file, read synchronously, rather than an async filesystem
        dependency for a single comparison.
        """

        try:
            return self._config_store.xray_config_path.read_text() == rendered
        except OSError:
            return False

    async def resync_served_config(self) -> bool:
        async with self._apply_lock:
            return await self._resync_served_config()

    async def _resync_served_config(self) -> bool:
        """Re-render what is served from the desired state already recorded.

        Provisioning only writes config when the *client set* changes, so a
        release that changes the config's shape -- new stats block, a new
        field on each client -- had no way to take effect. It would sit
        dormant until some unrelated user happened to provision, and activate
        at a moment nobody chose. This closes that: a restart is the deploy.

        Nothing about the desired state changes here, so there is no candidate
        to promote and no new last-known-good to record. Only the rendering
        moves.

        Never leaves the transport down. Validation runs against the store's
        scratch copy, so a config this build cannot even parse is rejected
        before the live file is touched; and if a validated config still fails
        to load, the exact bytes that were being served are written back and
        reloaded. A failed resync is reported, not raised -- the agent must
        come up and keep serving whatever it already had.
        """

        desired = self._config_store.read_last_known_good()
        rendered = self._render(desired)
        if self._xray_config_matches(rendered):
            # Hysteria still gets a look: its config is rendered separately
            # and can be stale on its own. `_apply_hysteria` no-ops when the
            # served file already matches.
            await self._apply_hysteria(desired)
            return False

        await self._validate(rendered)

        try:
            previous = self._config_store.xray_config_path.read_text()
        except OSError:
            previous = None

        self._config_store.write_xray_config_atomically(rendered)
        try:
            await self._reload()
        except ApplyError:
            if previous is not None:
                self._config_store.write_xray_config_atomically(previous)
                await self._reload()
            raise

        await self._apply_hysteria(desired)
        return True

    def _render_hysteria(self, profile: HysteriaServerProfile, desired: DesiredXrayState) -> str:
        clients = desired.clients_for(profile.protocol_profile_code)
        return render_hysteria_server_config(
            tuple(c.client_uuid for c in clients),
            profile,
            api_host=self._settings.xray_api_host,
            auth_url=self._hysteria_auth_url() if self._settings.xray_live_client_updates else None,
        )

    def _hysteria_auth_url(self) -> str:
        return f"http://{self._settings.xray_api_host}:{HYSTERIA_AUTH_PORT}{HYSTERIA_AUTH_PATH}"

    def authorize_hysteria(self, auth: str) -> str | None:
        """Whether a new Hysteria2 connection is one of ours, and as whom.

        `auth` is what the client presented: its UUID, or `uuid:uuid` in the
        userpass form. Admitted only if that UUID is recorded for the Hysteria
        profile -- the same last-known-good set every other check reads -- and
        admitted as its label, so Hysteria's logs, counters and `/kick` never
        carry the credential. Anything else is refused, including a UUID
        recorded for a different transport.
        """

        profile = self._hysteria_profile
        if profile is None:
            return None
        user, separator, password = auth.partition(":")
        if separator and user != password:
            return None
        try:
            client_uuid = UUID(user)
        except ValueError:
            return None
        if str(client_uuid) != user.lower():
            # Only the form the API issues. UUID() also accepts braces, URNs
            # and no hyphens, and there is no reason to.
            return None
        recorded = self._config_store.read_last_known_good().client(client_uuid)
        if recorded is None or recorded.protocol_profile_code != profile.protocol_profile_code:
            return None
        return client_email(client_uuid)

    def _hysteria_config_matches(self, rendered: str) -> bool:
        """Whether the served config is already what we would write. Read
        synchronously and deliberately: it is one small local file, and the
        alternative is an async filesystem dependency for a single compare."""

        try:
            return Path(self._settings.xray_hysteria_config_file).read_text() == rendered
        except OSError:
            # Nothing readable there yet -- treat as changed and write one.
            return False

    async def _apply_hysteria(self, desired: DesiredXrayState) -> None:
        """Write and restart, then confirm the unit is actually up.

        The binary has no `-test` equivalent, so unlike Xray there is no way
        to reject a bad config before it reaches the running service. The
        check afterwards is what stands in for that: a restart command can
        succeed while the process exits immediately on a config it cannot
        parse, and without this the caller would be told the client was
        provisioned while the transport was down.
        """

        profile = self._hysteria_profile
        if profile is None:
            return

        rendered = self._render_hysteria(profile, desired)
        if self._hysteria_config_matches(rendered):
            # Nothing about the Hysteria2 client set changed, so there is
            # nothing to apply. Restarting anyway would drop every live
            # Hysteria2 session each time an unrelated transport is
            # provisioned, and would add its restart-and-wait to an apply that
            # has nothing to do with it -- long enough for the API to time out
            # and leave the client stuck mid-revoke.
            return

        self._config_store.write_hysteria_config_atomically(
            rendered, self._settings.xray_hysteria_config_file
        )
        result = await run_fixed_argv(
            build_hysteria_reload_argv(),
            timeout_seconds=self._settings.xray_apply_timeout_seconds,
        )
        if result.returncode != 0:
            raise ApplyError(result.stderr.decode(errors="replace").strip())

        # Poll rather than ask once. `systemctl restart` returns as soon as the
        # process is spawned, and `is-active` reports "activating" -- exit 3 --
        # for a moment after that. Checking once turned a healthy restart into
        # apply_failed, which marked the client failed and left the next revoke
        # with nothing live to revoke: the app could not disconnect.
        deadline = time.monotonic() + _HYSTERIA_ACTIVE_TIMEOUT_SECONDS
        last = "unknown"
        while True:
            active = await run_fixed_argv(
                build_hysteria_is_active_argv(),
                timeout_seconds=self._settings.xray_apply_timeout_seconds,
            )
            last = active.stdout.decode(errors="replace").strip() or "inactive"
            if active.returncode == 0:
                return
            if last == "failed" or time.monotonic() >= deadline:
                break
            await asyncio.sleep(_HYSTERIA_ACTIVE_POLL_SECONDS)
        raise ApplyError(f"{_HYSTERIA_UNIT} did not come up: {last}")

    async def _rollback(self) -> None:
        last_known_good = self._config_store.read_last_known_good()
        self._config_store.write_xray_config_atomically(self._render(last_known_good))
        try:
            await self._reload()
            await self._apply_hysteria(last_known_good)
        except ApplyError as error:
            raise RollbackFailedError(str(error)) from error

    async def _apply_delta(self, desired: DesiredXrayState) -> None:
        previous = self._config_store.read_last_known_good()
        state_text = self._config_store.render_candidate(desired)
        state_candidate = self._config_store.write_candidate_atomically(state_text)

        server_config_text = self._render(desired)
        await self._validate(server_config_text)

        served = self._served_xray_config()
        self._config_store.write_xray_config_atomically(server_config_text)
        try:
            removed = await self._apply_xray(served, server_config_text)
            # Both processes serve the same provisioned client set, so a
            # client is only applied once both agree. A half-applied delta
            # is worse than a failed one: the caller would be told the
            # credential is live while one transport still rejects it.
            await self._apply_hysteria(desired)
        except ApplyError:
            await self._rollback()
            raise

        self._config_store.promote_candidate_to_last_known_good(state_candidate)
        self._watch_for_lingering(removed)
        # After promotion, not before: a kicked client reconnects at once, and
        # it has to find itself refused.
        await self._kick_removed_hysteria_clients(previous, desired)

    async def _kick_removed_hysteria_clients(
        self, previous: DesiredXrayState, desired: DesiredXrayState
    ) -> None:
        """Close the open connections of Hysteria2 clients just removed.

        Removal only stops new connections being admitted. A restart used to
        close the rest -- everyone's -- and `/kick` closes exactly these.
        Best effort: a kick that fails leaves a revoked client's existing
        sessions running until they end, and says so in the log.
        """

        profile = self._hysteria_profile
        if profile is None or not self._settings.xray_live_client_updates:
            return
        code = profile.protocol_profile_code
        kept = {c.client_uuid for c in desired.clients_for(code)}
        labels = sorted(
            client_email(c.client_uuid)
            for c in previous.clients_for(code)
            if c.client_uuid not in kept
        )
        if not labels:
            return
        url = f"http://{self._settings.xray_api_host}:{TRAFFIC_STATS_PORT}/kick"
        try:
            await asyncio.to_thread(_post_hysteria_kick, url, traffic_stats_secret(profile), labels)
        except (urllib.error.URLError, OSError, ValueError) as error:
            _LOGGER.warning(
                "could not kick %d removed Hysteria2 client(s): %s", len(labels), str(error)[:200]
            )

    def _served_xray_config(self) -> str | None:
        try:
            return self._config_store.xray_config_path.read_text()
        except OSError:
            return None

    async def _apply_xray(self, served: str | None, rendered: str) -> set[str]:
        """Bring the running Xray to `rendered`, which is already on disk.

        Returns the emails of clients removed through the API, which a
        restart would have disconnected and the API does not.
        """

        if not self._settings.xray_live_client_updates:
            await self._reload()
            return set()
        before = _shape_without_clients(served) if served is not None else None
        if before is None or before != _shape_without_clients(rendered):
            # More than the client lists changed, or there was nothing being
            # served to change. Only a restart applies that.
            await self._reload()
            return set()
        try:
            return await self._apply_clients_live(rendered)
        except ApplyError as error:
            # The file already says what should be served, so a restart
            # still lands on exactly the intended set.
            _LOGGER.warning("live client update failed, restarting Xray instead: %s", error)
            await self._reload()
            return set()

    async def _apply_clients_live(self, rendered: str) -> set[str]:
        wanted = _live_inbounds_by_tag(rendered)
        removed: set[str] = set()
        additions: list[dict[str, object]] = []
        for tag, inbound in wanted.items():
            clients = inbound.clients
            live = await self._live_emails(tag)
            gone = live - clients.keys()
            if gone:
                # Named by email, which is a digest (see client_email): an
                # argv is visible to every local user, and a UUID there would
                # hand out the credential it names.
                await self._xray_api("rmu", f"-tag={tag}", *sorted(gone))
                removed |= gone
            new = [clients[email] for email in sorted(clients.keys() - live)]
            if new:
                additions.append(
                    {
                        "tag": tag,
                        "protocol": inbound.protocol,
                        "port": inbound.port,
                        "settings": {**inbound.settings, "clients": new},
                    }
                )
        if additions:
            # Over stdin, because this carries each new client's UUID -- the
            # credential itself -- and neither a file nor an argv is somewhere
            # it should be.
            payload = json.dumps({"inbounds": additions}).encode()
            await self._xray_api("adu", "stdin:", stdin=payload)

        # `adu` exits 0 even when Xray refused the user, so what Xray now
        # holds is the only evidence the change took.
        for tag, inbound in wanted.items():
            clients = inbound.clients
            if await self._live_emails(tag) != clients.keys():
                raise ApplyError(f"Xray's live clients for {tag} do not match the rendered set")
            for email in clients:
                # Served again -- a reconnect, most likely -- so its traffic
                # is not a connection that outlived its removal.
                self._lingering.pop(email, None)
        return removed

    async def _xray_api(self, command: str, *arguments: str, stdin: bytes | None = None) -> bytes:
        argv = [
            str(self._settings.xray_binary),
            "api",
            command,
            f"--server={self._settings.xray_api_host}:{STATS_API_PORT}",
            *arguments,
        ]
        result = await run_fixed_argv(argv, timeout_seconds=_XRAY_API_TIMEOUT_SECONDS, stdin=stdin)
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()[:200]
            raise ApplyError(f"xray api {command} failed: {detail}")
        return result.stdout

    async def _live_emails(self, tag: str) -> set[str]:
        """The emails of the clients Xray is serving on one inbound right now.

        Its output carries each client's UUID too. It is read here and not
        kept, logged or returned.
        """

        output = await self._xray_api("inbounduser", f"-tag={tag}")
        try:
            payload = json.loads(output.decode(errors="replace") or "{}")
        except json.JSONDecodeError as error:
            raise ApplyError("xray api inbounduser returned unparseable output") from error
        users = payload.get("users", []) if isinstance(payload, dict) else []
        return {
            str(user["email"]) for user in users if isinstance(user, dict) and user.get("email")
        }

    def _watch_for_lingering(self, removed: set[str]) -> None:
        """Keep an eye on clients removed through the API.

        Removing a client refuses its new connections and leaves its open
        ones running. A disconnect has already closed them, so that is
        harmless -- but a revoke for a spent allowance, or by an
        administrator, has to actually stop the traffic. So each removed
        client's counters are watched, and if they move, Xray is restarted,
        which closes everything. Rare by construction: it needs someone still
        transferring after their own removal.
        """
        if not removed:
            return
        now = time.monotonic()
        for email in removed:
            self._lingering[email] = _Lingering(removed_at=now)
        if self._linger_task is None or self._linger_task.done():
            self._linger_task = asyncio.get_running_loop().create_task(self._cut_off_lingering())

    async def _cut_off_lingering(self) -> None:
        while self._lingering:
            await asyncio.sleep(_LINGER_POLL_SECONDS)
            try:
                totals = await self._user_traffic_totals()
            except ApplyError as error:
                _LOGGER.warning("could not read counters for removed clients: %s", error)
                continue
            now = time.monotonic()
            moved = False
            for email, watch in list(self._lingering.items()):
                total = totals.get(email, 0)
                if watch.baseline is None:
                    # The first reading after removal is the baseline, so
                    # bytes counted before it -- a disconnect's last packets
                    # included -- are never taken for new traffic.
                    watch.baseline = total
                elif total > watch.baseline:
                    moved = True
                elif now - watch.removed_at >= _LINGER_WATCH_SECONDS:
                    del self._lingering[email]
            if moved:
                await self._restart_for_lingering()
                return

    async def _restart_for_lingering(self) -> None:
        async with self._apply_lock:
            if not self._lingering:
                # Every one of them was served again while waiting for the
                # lock; there is nothing to cut off.
                return
            _LOGGER.warning(
                "restarting Xray: %d removed client(s) still had traffic", len(self._lingering)
            )
            self._lingering.clear()
            try:
                await self._reload()
            except ApplyError as error:
                _LOGGER.error("restart to close removed clients' connections failed: %s", error)

    async def _user_traffic_totals(self) -> dict[str, int]:
        output = await self._xray_api("statsquery", "-pattern", "user>>>")
        try:
            payload = json.loads(output.decode(errors="replace") or "{}")
        except json.JSONDecodeError as error:
            raise ApplyError("xray api statsquery returned unparseable output") from error
        totals: dict[str, int] = {}
        rows = payload.get("stat", []) if isinstance(payload, dict) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            parts = str(row.get("name", "")).split(">>>")
            if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
                continue
            totals[parts[1]] = totals.get(parts[1], 0) + int(row.get("value", 0) or 0)
        return totals

    def _response_common(self, protocol_profile_code: str) -> dict[str, object]:
        """Endpoint details the API hands to the client, for either engine.

        Hysteria2's fields come from its own profile rather than an Xray
        inbound, but the shape the API sees is identical -- the client does
        not need to know which binary answers the port.
        """

        base: dict[str, object] = {
            "server_address": self._settings.xray_public_host,
            "sni": self._settings.xray_sni,
        }
        hysteria = self._hysteria_profile
        if hysteria is not None and hysteria.protocol_profile_code == protocol_profile_code:
            return {
                **base,
                "port": hysteria.port,
                "transport": "hysteria",
                "transport_security": "tls",
                "path": None,
                "service_name": None,
                "obfs_password": hysteria.obfs_password,
            }
        profile = self._profile_for(protocol_profile_code)
        # These describe what the CLIENT dials, which is not always what the
        # inbound binds. A profile with security="none" is loopback-only with
        # nginx terminating TLS in front of it, so the client connects to the
        # public port over TLS and never sees the inbound's own port or its
        # lack of encryption. Reporting the inbound's values sent clients to a
        # loopback port that answers nothing -- measured as zero packets on the
        # public port while every directly-bound transport worked.
        fronted = profile.security == "none" and not profile.direct
        return {
            **base,
            "port": self._settings.xray_public_port if fronted else profile.port,
            "transport": profile.transport,
            "transport_security": "tls" if fronted else profile.security,
            "path": profile.xhttp_path or profile.ws_path,
            "service_name": profile.grpc_service_name,
            "obfs_password": profile.hysteria_obfs_password,
        }

    def _client_fields(self, protocol_profile_code: str, client_uuid: UUID) -> dict[str, object]:
        """What a client of a direct, self-encrypted profile needs beyond the
        endpoint: its protocol and that protocol's own key material."""

        profile = next(
            (p for p in self._profiles if p.protocol_profile_code == protocol_profile_code), None
        )
        if profile is None:
            return {}
        if profile.ss2022_server_key is not None:
            return {
                "protocol": "shadowsocks",
                "method": SS2022_METHOD,
                "password": f"{profile.ss2022_server_key}:{ss2022_user_key(client_uuid)}",
            }
        if profile.vmess:
            return {"protocol": "vmess"}
        if profile.vless_encryption is not None:
            return {"encryption": profile.vless_encryption}
        return {}

    def advertised_endpoints(self) -> tuple[tuple[str, str, int, str], ...]:
        """(profile code, host, port, transport) for every profile served.

        Exactly what a client would be told to dial, taken from
        _response_common rather than recomputed, so that a preflight check
        built on this can catch a mistake in that computation. Recomputing the
        fronted/direct split here independently would reproduce whatever it
        got wrong and agree with it -- which is how the XHTTP endpoint stayed
        broken through several investigations.
        """

        codes = [profile.protocol_profile_code for profile in self._profiles]
        if self._hysteria_profile is not None:
            codes.append(self._hysteria_profile.protocol_profile_code)
        endpoints = []
        for code in codes:
            common = self._response_common(code)
            endpoints.append(
                (
                    code,
                    str(common["server_address"]),
                    int(str(common["port"])),
                    str(common["transport"]),
                )
            )
        return tuple(endpoints)

    async def provision_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        async with self._apply_lock:
            return await self._provision_client(request)

    async def _provision_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        if not self._serves(request.protocol_profile_code):
            raise ValidationError(
                f"no configured inbound for profile {request.protocol_profile_code!r}"
            )
        client = RenderedXrayClient(
            client_uuid=request.client_uuid,
            protocol_profile_code=request.protocol_profile_code,
            generation=request.desired_generation,
        )
        current = self._config_store.read_last_known_good()
        common = self._response_common(request.protocol_profile_code)
        common = {
            **common,
            **self._client_fields(request.protocol_profile_code, request.client_uuid),
        }
        try:
            await self._apply_delta(current.with_client(client))
        except (ValidationError, ApplyError):
            return ProvisionXrayClientResponse(
                state="failed",
                applied_generation=self._last_applied_generation(current, request.client_uuid),
                error_code="apply_failed",
                **common,
            )
        return ProvisionXrayClientResponse(
            state="active", applied_generation=request.desired_generation, **common
        )

    async def revoke_client(self, request: RevokeXrayClientRequest) -> RevokeXrayClientResponse:
        async with self._apply_lock:
            return await self._revoke_client(request)

    async def _revoke_client(self, request: RevokeXrayClientRequest) -> RevokeXrayClientResponse:
        if not self._serves(request.protocol_profile_code):
            raise ValidationError(
                f"no configured inbound for profile {request.protocol_profile_code!r}"
            )
        current = self._config_store.read_last_known_good()
        try:
            await self._apply_delta(current.without_client(request.client_uuid))
        except (ValidationError, ApplyError):
            return RevokeXrayClientResponse(
                state="failed",
                applied_generation=self._last_applied_generation(current, request.client_uuid),
                revoked_at=datetime.now(UTC),
                error_code="apply_failed",
            )
        return RevokeXrayClientResponse(
            state="revoked",
            applied_generation=request.desired_generation,
            revoked_at=datetime.now(UTC),
        )

    async def prune_clients(self, request: PruneXrayClientsRequest) -> PruneXrayClientsResponse:
        async with self._apply_lock:
            return await self._prune_clients(request)

    async def _prune_clients(self, request: PruneXrayClientsRequest) -> PruneXrayClientsResponse:
        """Drops every client this agent still holds that is absent from the
        caller's expected set, in a single apply.

        One apply rather than a revoke per orphan on purpose: each apply
        restarts the Xray process, dropping every live connection on every
        inbound, so pruning N orphans one at a time would mean N such drops
        (and, before this unit's start limit was raised, would simply start
        failing partway through). The state is re-rendered whole on every
        apply anyway, so removing them together costs exactly one."""

        current = self._config_store.read_last_known_good()
        keep = {expected.client_uuid for expected in request.expected}
        survivors = tuple(c for c in current.clients if c.client_uuid in keep)
        removed = len(current.clients) - len(survivors)

        # Bookkeeping is not the authority on what is being served. A client
        # written straight into the config file -- by hand, by a half-finished
        # experiment, by anything that is not this driver -- never appears in
        # last-known-good, so the comparison above cannot see it and it
        # survives every sweep. Ask the served files as well.
        #
        # The apply below re-renders the whole config from `survivors`, so it
        # already removes such a client; the only thing missing was a reason
        # to run when bookkeeping alone looked clean.
        unaccounted = self._unaccounted_live_uuids(keep, current.clients)
        if removed == 0 and not unaccounted:
            # Nothing to do -- deliberately not applying, so a routine sweep on
            # a healthy server never restarts Xray and never disturbs a live
            # connection just to confirm there was nothing to remove.
            return PruneXrayClientsResponse(state="pruned", removed=0, kept=len(survivors))
        if unaccounted:
            _LOGGER.warning(
                "pruning %d credential(s) present in the served config but in no "
                "database row and no local bookkeeping",
                len(unaccounted),
            )
        try:
            await self._apply_delta(DesiredXrayState(clients=survivors))
        except (ValidationError, ApplyError):
            return PruneXrayClientsResponse(
                state="failed", removed=0, kept=len(current.clients), error_code="apply_failed"
            )
        return PruneXrayClientsResponse(
            state="pruned", removed=removed + len(unaccounted), kept=len(survivors)
        )

    def _unaccounted_live_uuids(
        self, keep: set[UUID], recorded: tuple[RenderedXrayClient, ...]
    ) -> set[str]:
        """Credentials the served files carry that nothing else knows about.

        Both the caller's expected set and this driver's own bookkeeping are
        subtracted, so this is strictly the credentials no side accounts for.
        A client that is recorded but no longer expected is an ordinary
        prune -- already counted by the caller -- and counting it here as well
        would double it.

        Read from the files the two server processes actually load, not from
        this driver's record of what it wrote -- a credential injected into
        the config directly is invisible to bookkeeping by construction, which
        is exactly the case worth catching.

        An unreadable config returns empty rather than raising: this is a
        supplementary check inside a routine sweep, and failing the prune
        because one file could not be parsed would turn a partial view into an
        outage. The reconcile path reports that condition properly.
        """

        known = {str(client_uuid) for client_uuid in keep}
        known |= {str(client.client_uuid) for client in recorded}
        live: set[str] = set()
        for profile in self._profiles:
            try:
                live |= self._live_client_uuids(profile)
            except (OSError, ValueError):
                return set()
        if self._hysteria_profile is not None:
            try:
                live |= self._live_hysteria_uuids()
            except (OSError, ValueError):
                return set()
        return live - known

    async def reconcile_client(
        self, request: ReconcileXrayClientRequest
    ) -> ReconcileXrayClientResponse:
        """Compares two independent views, mirroring NativeWireGuardDriver's
        reconcile: the config file the Xray process actually reads, and this
        driver's own last-known-good bookkeeping (which is the only one of the
        two that knows generations). Both must agree for in_sync.

        A client recorded under a different profile than the request names is
        reported ambiguous rather than drift: the UUID exists, so revoking it
        as absent would be wrong, but it is not serving what the API believes
        either, and guessing which side is stale is exactly the call this
        driver must never make on its own."""

        hysteria = self._hysteria_profile
        is_hysteria = (
            hysteria is not None and hysteria.protocol_profile_code == request.protocol_profile_code
        )
        profile: XrayInboundProfile | None = None
        if not is_hysteria:
            try:
                profile = self._profile_for(request.protocol_profile_code)
            except ValidationError:
                # Unlike provision/revoke, an unknown profile must not propagate
                # as a 500 here: reconciliation sweeps whatever the API has rows
                # for, and a profile this agent no longer serves is drift to
                # report, not a crash to raise mid-sweep.
                return ReconcileXrayClientResponse(outcome="ambiguous", observed_generation=None)

        recorded = self._config_store.read_last_known_good().client(request.client_uuid)
        try:
            live_uuids = (
                self._live_hysteria_uuids() if profile is None else self._live_client_uuids(profile)
            )
        except (OSError, ValueError):
            return ReconcileXrayClientResponse(
                outcome="ambiguous", observed_generation=None, error_code="config_unreadable"
            )

        # str(), not the UUID itself: the config file stores these as strings,
        # and a UUID never compares equal to its own string form.
        present_live = str(request.client_uuid) in live_uuids
        if recorded is None or not present_live:
            # Both views must show it gone to call it clean drift; disagreement
            # between them means an apply landed in one place and not the other.
            if recorded is None and not present_live:
                return ReconcileXrayClientResponse(
                    outcome="drift_detected", observed_generation=None
                )
            return ReconcileXrayClientResponse(
                outcome="ambiguous",
                observed_generation=None if recorded is None else recorded.generation,
            )

        if recorded.protocol_profile_code != request.protocol_profile_code:
            return ReconcileXrayClientResponse(
                outcome="ambiguous", observed_generation=recorded.generation
            )
        return ReconcileXrayClientResponse(
            outcome="in_sync", observed_generation=recorded.generation
        )

    def _live_hysteria_uuids(self) -> set[str]:
        """The credentials the running Hysteria2 process actually has, read
        back from its own config file for the same reason as the Xray side:
        reconciliation is only worth anything if it consults the served file
        rather than this driver's own bookkeeping.

        The placeholder user a client-less config has to carry is not a
        credential and is left out. Counted, it was a credential no database
        row accounts for, so every orphan prune "removed" it -- restarting Xray
        and dropping every connection on the server -- and the re-render put it
        straight back, every fifteen minutes.
        """

        text = Path(self._settings.xray_hysteria_config_file).read_text()
        if "\n  type: http\n" in text:
            # No list to read: Hysteria asks authorize_hysteria, which admits
            # exactly the recorded set. That set is what it serves.
            profile = self._hysteria_profile
            if profile is None:
                return set()
            recorded = self._config_store.read_last_known_good()
            return {str(c.client_uuid) for c in recorded.clients_for(profile.protocol_profile_code)}
        live: set[str] = set()
        in_userpass = False
        for line in text.splitlines():
            if line.startswith("  userpass:"):
                in_userpass = True
                continue
            if in_userpass:
                # The map ends at the first line that is not one of its
                # entries; entries are rendered at exactly four spaces.
                if not line.startswith("    ") or line.strip() in {"", "{}"}:
                    break
                key = line.strip().split(":", 1)[0].strip().strip('"')
                if key and key != NO_CLIENTS_USER:
                    live.add(key)
        return live

    def _live_client_uuids(self, profile: XrayInboundProfile) -> set[str]:
        """The client set the running Xray process actually has for this
        inbound, read back from its own config file rather than inferred from
        this driver's bookkeeping -- that independence is the whole point of
        reconciling."""

        config = json.loads(self._config_store.xray_config_path.read_text())
        for inbound in config.get("inbounds", []):
            if inbound.get("port") != profile.port:
                continue
            clients = inbound.get("settings", {}).get("clients", [])
            # VLESS inbounds identify a client by "id", Hysteria2 by "auth",
            # Shadowsocks-2022 by a key made from the UUID.
            if profile.ss2022_server_key is not None:
                return {str(uuid_from_ss2022_key(str(c.get("password")))) for c in clients}
            return {str(c.get("id") or c.get("auth")) for c in clients}
        return set()

    async def health(self, request: XrayHealthRequest) -> XrayHealthResponse:
        """No `wg show dump` equivalent exists for Xray; a bare TCP connect
        to its own loopback listener is a liveness probe (proves the process
        is up and accepting connections), not a protocol-correctness check --
        deliberately no new subprocess surface for this. Only the loopback
        XHTTP inbound is probed -- it is the one inbound guaranteed to exist
        regardless of which optional transports are enabled."""

        client_count = len(self._config_store.read_last_known_good().clients)
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self._settings.xray_local_listen_port),
                timeout=_HEALTH_TIMEOUT_SECONDS,
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, TimeoutError):
            return XrayHealthResponse(
                state="unreachable",
                observed_at=datetime.now(UTC),
                agent_version=__version__,
                listener_up=False,
                client_count=client_count,
                error_code="listener_unreachable",
            )
        return XrayHealthResponse(
            state="healthy",
            observed_at=datetime.now(UTC),
            agent_version=__version__,
            listener_up=True,
            client_count=client_count,
        )


def _shape_without_clients(config_text: str) -> str | None:
    """A config with its VLESS client lists emptied, for comparing shapes.

    Two configs with the same shape differ only in which VLESS clients they
    serve, which the API can change live. None for text that does not parse:
    that can only be compared by restarting.
    """

    try:
        config = json.loads(config_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(config, dict):
        return None
    for inbound in config.get("inbounds", []):
        if isinstance(inbound, dict) and inbound.get("protocol") in _LIVE_PROTOCOLS:
            settings = inbound.get("settings")
            if isinstance(settings, dict):
                settings["clients"] = []
    return json.dumps(config, sort_keys=True)


# Inbounds whose users Xray's API adds and removes without a restart.
_LIVE_PROTOCOLS = ("vless", "shadowsocks", "vmess")


@dataclass(frozen=True, slots=True)
class _LiveInbound:
    port: int
    protocol: str
    # The inbound's settings without its clients: what `adu` needs to build
    # a user for it (Shadowsocks needs the method and server key).
    settings: dict[str, object]
    clients: dict[str, dict[str, str]]


def _live_inbounds_by_tag(config_text: str) -> dict[str, _LiveInbound]:
    """Each VLESS, VMess and Shadowsocks inbound, its clients keyed by email."""

    config = json.loads(config_text)
    result: dict[str, _LiveInbound] = {}
    for inbound in config.get("inbounds", []):
        protocol = inbound.get("protocol")
        if protocol not in _LIVE_PROTOCOLS:
            continue
        settings = dict(inbound.get("settings", {}))
        clients = {
            str(client["email"]): {k: str(v) for k, v in client.items()}
            for client in settings.pop("clients", [])
        }
        result[str(inbound["tag"])] = _LiveInbound(
            int(inbound["port"]), str(protocol), settings, clients
        )
    return result


def _post_hysteria_kick(url: str, secret: str, labels: list[str]) -> None:
    """POST Hysteria2's `/kick` with the labels to disconnect.

    Blocking, so the caller runs it off the event loop; a module-level
    function so a test can replace it. stdlib rather than a client library,
    like the usage collector's read of the same API.
    """

    request = urllib.request.Request(  # noqa: S310 - fixed http:// loopback URL
        url,
        data=json.dumps(labels).encode(),
        headers={"Authorization": secret, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_XRAY_API_TIMEOUT_SECONDS) as response:  # noqa: S310
        if response.status != 200:
            raise ValueError(f"hysteria kick answered {response.status}")
