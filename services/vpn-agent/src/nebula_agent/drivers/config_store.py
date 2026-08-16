"""Atomic on-disk WireGuard interface state: desired-state deltas, candidate
render/write, promotion to last-known-good, and rollback.

Shared by FakeWireGuardRunner and (from milestone 5) NativeWireGuardDriver --
the fake driver can exercise the exact same file-management logic the real
driver does, just without any subprocess call at the validate/apply steps.
"""

import os
import tempfile
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path, PurePosixPath

IPAddress = IPv4Address | IPv6Address


def _host_cidr(address: IPAddress) -> str:
    prefix = 32 if address.version == 4 else 128
    return f"{address}/{prefix}"


@dataclass(frozen=True, slots=True)
class RenderedPeer:
    public_key: str
    assigned_address: IPAddress
    persistent_keepalive_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class DesiredInterfaceState:
    """The full peer set the next candidate should contain -- always complete,
    matching how `wg syncconf` applies a full desired state as a diff against
    the live interface, not an incremental patch."""

    peers: tuple[RenderedPeer, ...] = ()

    def with_peer(self, peer: RenderedPeer) -> "DesiredInterfaceState":
        """Add the peer, or replace the existing entry with the same public key."""
        remaining = tuple(p for p in self.peers if p.public_key != peer.public_key)
        return DesiredInterfaceState(peers=(*remaining, peer))

    def without_peer(self, public_key: str) -> "DesiredInterfaceState":
        return DesiredInterfaceState(
            peers=tuple(p for p in self.peers if p.public_key != public_key)
        )

    def peer(self, public_key: str) -> RenderedPeer | None:
        return next((p for p in self.peers if p.public_key == public_key), None)


def render_wireguard_config(desired: DesiredInterfaceState) -> str:
    """Render [Peer]-only config text -- `wg syncconf` only reads [Interface]
    ListenPort/PrivateKey/FwMark and [Peer] blocks, diffing peers against the
    live interface. Interface identity is set once at boot by wg-quick, not
    per operation, so it is deliberately not rendered here."""

    lines: list[str] = []
    for peer in desired.peers:
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer.public_key}")
        lines.append(f"AllowedIPs = {_host_cidr(peer.assigned_address)}")
        if peer.persistent_keepalive_seconds is not None:
            lines.append(f"PersistentKeepalive = {peer.persistent_keepalive_seconds}")
        lines.append("")
    return "\n".join(lines)


def parse_wireguard_config(text: str) -> DesiredInterfaceState:
    """Parse text this module rendered. Only understands the exact subset of
    wg-config syntax render_wireguard_config produces -- not a general-purpose
    WireGuard config parser."""

    peers: list[RenderedPeer] = []
    public_key: str | None = None
    address: IPAddress | None = None
    keepalive: int | None = None

    def flush() -> None:
        nonlocal public_key, address, keepalive
        if public_key is not None and address is not None:
            peers.append(
                RenderedPeer(
                    public_key=public_key,
                    assigned_address=address,
                    persistent_keepalive_seconds=keepalive,
                )
            )
        public_key = None
        address = None
        keepalive = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line == "[Peer]":
            flush()
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "PublicKey":
            public_key = value
        elif key == "AllowedIPs":
            address = ip_address(value.split("/", 1)[0])
        elif key == "PersistentKeepalive":
            keepalive = int(value)
    flush()
    return DesiredInterfaceState(peers=tuple(peers))


class ConfigStore:
    """Owns the on-disk atomic apply + rollback state for one WireGuard interface.

    Layout under state_dir:
      <interface>.conf           -- last-known-good peer set, the only file a
                                     restart should ever read back from
      <interface>.conf.candidate -- a just-rendered, not-yet-promoted candidate
    """

    def __init__(self, state_dir: PurePosixPath, interface: str) -> None:
        self._dir = Path(str(state_dir))
        self._interface = interface

    @property
    def last_known_good_path(self) -> Path:
        return self._dir / f"{self._interface}.conf"

    @property
    def candidate_path(self) -> Path:
        return self._dir / f"{self._interface}.conf.candidate"

    def read_last_known_good(self) -> DesiredInterfaceState:
        """The baseline every operation computes its delta against -- read
        from disk, not a live `wg show`, so apply is always against a known
        baseline even if the kernel state was hand-modified out of band."""

        if not self.last_known_good_path.exists():
            return DesiredInterfaceState()
        return parse_wireguard_config(self.last_known_good_path.read_text())

    def render_candidate(self, desired: DesiredInterfaceState) -> str:
        return render_wireguard_config(desired)

    def write_candidate_atomically(self, text: str) -> Path:
        self._dir.mkdir(parents=True, exist_ok=True)
        descriptor, tmp_name = tempfile.mkstemp(dir=self._dir, prefix=f".{self._interface}.")
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.candidate_path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        return self.candidate_path

    def promote_candidate_to_last_known_good(self, candidate: Path) -> None:
        """Called only after the caller has confirmed the candidate was applied successfully."""

        os.replace(candidate, self.last_known_good_path)

    def rollback_text(self) -> str:
        """The text to re-apply in order to restore the last-known-good state."""

        if not self.last_known_good_path.exists():
            return render_wireguard_config(DesiredInterfaceState())
        return self.last_known_good_path.read_text()
