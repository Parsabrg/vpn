# ADR 0004: One tunnel, several engines -- Xray and DNS tunnelling side by side

- Status: proposed
- Date: 2026-09-03

## Context

The app must carry every Xray transport this deployment offers (VLESS over
XHTTP, gRPC, WebSocket and raw TCP, REALITY, XTLS Vision, Hysteria2) and, in
addition, DNS tunnelling -- a different family entirely, useful precisely when
the proxy transports are blocked. WireGuard exists alongside as its own native
integration.

Today the four TCP transports work. Hysteria2 had two independent faults, both
now understood: the client transmits nothing, and Xray-core's server-side
implementation silently discarded the obfuscation it was configured with. ADR
0003 has the measurements. The server half is fixed -- Hysteria2 now runs on the
standalone reference binary and is confirmed working from the target network --
and the client half is not.

That split is itself the argument for this ADR: one core could not carry all
three families, and there was no seam where the second could be added.

Two working clients were read on the operator's own device and network rather
than reasoned about.

**v2rayNG** runs Hysteria2 successfully on the same handset where this app
cannot:

- `CoreVpnService` calls `builder.addDisallowedApplication(selfPackageName)`,
  making the app's own sockets exempt from its own tunnel as a routing fact
  rather than a per-socket call.
- `CoreServiceManager` picks the packet path at runtime:
  `var tunFd = vpnInterface?.fd ?: 0`, sometimes reset to `0`, then
  `coreController.startLoop(config, tunFd)`. Non-zero lets the core own the
  interface; zero leaves it to a bridge.
- `Tun2SocksControl` is an **interface** with swappable implementations.

**WhiteDNS-Android** ships `WhiteDnsVpnService` and `WhiteDnsProxyService` as
peers over `tun2proxy`.

Both keep the interface decoupled from whatever moves the bytes.

## Decision

One `VpnService` owning one interface, with **engines** behind it and the
packet path chosen per session rather than fixed.

```
NebulaVpnService            owns TUN, excludes own package, supervises
  |
  +-- PacketPath  (chosen at start, not hardcoded)
  |     A: hand the TUN fd to a single engine        <- default, fastest
  |     B: bridge TUN <-> local SOCKS                <- when composing engines
  |
  +-- Engine(s)
        XrayEngine         VLESS/XHTTP/gRPC/WS/TCP, REALITY, Vision
        Hysteria2Engine    real Hysteria2 -- NOT Xray's, see D4/D5
        DnsTunnelEngine    DNS tunnelling; also exposes a local SOCKS
        (WireGuardEngine)  existing integration, adopted into the interface
```

### D0. Component inventory

Both halves are taken from the two clients that demonstrably work, rather than
chosen fresh. Nothing here is speculative; each is pinned and each is read
rather than assumed.

| Piece | Upstream | Licence | How it is consumed |
|---|---|---|---|
| Xray core | `2dust/AndroidLibXrayLite` (bundles `xray-core@v1.260327.1`) | LGPL-3.0 | `libv2ray.aar`, current release, driven directly. **TCP transports only** |
| Hysteria2 server | `apernet/hysteria`, standalone binary | MIT | `nebula-hysteria.service`, already deployed |
| Hysteria2 client | Mihomo `hysteria2.go`, or upstream library | MIT | see D5; not yet chosen |
| TUN <-> SOCKS bridge | `hev-socks5-tunnel` | MIT | built per ABI, as v2rayNG does |
| DNS tunnel engine | `WhiteDNS/CottenDns` | MIT | git submodule pinned at `8eea49d1267b1a41441c25c75e69e6f12ad0a11f`, built `CGO_ENABLED=0` per ABI |
| DNS tunnel server | same repo, `cmd/server` | MIT | authoritative DNS on the VPS |

The DNS lineage is MasterDnsVPN -> StormDNS -> CottenDNS, MIT throughout, and
CottenDNS keeps wire compatibility with the older clients. It is the actively
maintained head of that line and the one WhiteDNS ships.

Note the two engines are consumed differently and that is deliberate: Xray is a
library linked into the process, CottenDNS is a **standalone binary run as a
subprocess** -- which is how it is built for Android (`CGO_ENABLED=0`, arm64 /
armv7 / amd64 / 386) and how WhiteDNS manages it. The subprocess inherits the
app's UID, so the package exclusion in D2 exempts its DNS egress from the
tunnel automatically rather than by special arrangement.

### D1. The packet path is a runtime choice, not an architectural one

Handing the descriptor to one engine is faster and handles UDP, ICMP and
full-cone NAT better than a SOCKS bridge. Bridging is what allows two engines
to compose. Both are needed, both are already supported by the library, and
v2rayNG demonstrates switching between them.

Engines therefore declare capability:

```dart
abstract interface class TunnelEngine {
  bool get canOwnTun;          // accepts a TUN fd directly
  bool get providesSocks;      // can be composed behind or beneath another

  Future<void> start(EngineConfig config, {int? tunFd, int? socksPort});
  Future<void> stop();
  Stream<EngineState> get state;
  Future<EngineStats> stats();
  Future<HealthResult> checkHealth();
}
```

Rule: **one engine, path A; composition, path B.** A profile needing only Xray
gets the fast path; DNS-tunnel-underneath-Xray gets the bridge. Choosing per
session means neither case is compromised for the other.

### D2. DNS is designed explicitly, because it is where the bugs live

Three resolution paths must never be confused. This session's outage was
exactly this: removing a pre-resolver left the core trying to resolve the
server's hostname through the tunnel it was building.

| Path | Resolves | Route | Rule |
|---|---|---|---|
| Bootstrap | the VPN server's own hostname | outside the tunnel, system DNS | resolved **before** the interface is established, cached for the session |
| In-tunnel | user traffic | inside the tunnel | never leaks to the local resolver |
| Engine egress | the DNS tunnel's own queries | outside the tunnel, always | must never route through itself |

Consequences that are non-negotiable:

- The API returns, and the client uses, **an IP address plus a separate SNI**
  for the server endpoint. Names are resolved before establishment or not at
  all. A profile is invalid if it cannot be dialled without in-tunnel DNS.
- The tunnel always declares its own DNS servers. Absent, Android falls back to
  the underlying network's resolver, which on this network forges answers --
  observed returning RFC1918 addresses for public names. That defeats the
  tunnel for censored names before any connection is attempted.
- `DnsTunnelEngine`'s upstream queries are pinned to the underlying network and
  exempt from the tunnel by the same package exclusion that exempts every other
  engine socket.

### D3. Composition is routing, not special-casing

CottenDNS's client already exposes **SOCKS5 on `127.0.0.1:18000`**, which is
the whole composition mechanism -- nothing has to be built for it. Three
arrangements follow:

- **Alone** -- the bridge points at `127.0.0.1:18000`; all traffic leaves as
  DNS.
- **Beneath Xray** -- Xray's outbound dials through that listener, so a proxy
  protocol runs over DNS when direct egress is blocked.
- **Selective** -- Xray routing rules send only some destinations through it.

The second and third fall out of the first. No engine knows about another; they
compose through a SOCKS port and routing rules.

Configuration is TOML with published presets (`speed`, `survival`,
`tcp-survival`); the wrapper passes equivalent values rather than inventing its
own. Carriers are UDP/53 and TCP/53 with optional DoT and DoH, selected
adaptively per resolver.

Encryption must be one of the authenticated AES-GCM methods (`3`, `4`, `5`).
Methods `1` and `2` (XOR, ChaCha20) exist for compatibility with the older
MasterDNS and StormDNS clients and **do not authenticate frames**; they are not
to be offered here.

Worth stating plainly because it affects what we promise users: a DNS tunnel is
slower than a proxy transport by design, and its volume and timing remain
recognisable to a capable observer. It is the transport for when the others are
blocked, not a general-purpose default.

### D4. Xray carries the TCP transports; Hysteria2 does not run on Xray

Xray-core is kept for VLESS over XHTTP, gRPC, WebSocket and raw TCP, plus
REALITY and Vision. Those four are proven on this network and there is no
reason to move them.

Hysteria2 is **not** an Xray transport here. Xray-core accepts
`streamSettings.udpmasks` and silently ignores it -- a client offering a
deliberately wrong Salamander password authenticates successfully -- so an
inbound configured for obfuscation has none, and a client applying real
Salamander cannot talk to it at all. Its Hysteria bandwidth fields are ignored
the same way, which the core reports at every startup. ADR 0003 has the
measurements.

Hysteria2 therefore runs on the standalone reference binary, server-side under
`nebula-hysteria.service`, and needs a real Hysteria2 implementation on the
client rather than Xray's.

That is the decisive change to this ADR's first draft, which assumed one core
could carry everything. It cannot, and the seam below is what makes that
survivable rather than fatal.

Separately, the app's Xray integration is still wrong in two ways it inherited
from `flutter_v2ray_client`: it arms a legacy protected dialer -- `useProtector`
plus `setProtectorServer`, absent from v2rayNG's build -- which hand-builds a
*stream* connection because it predates any UDP transport, and it never excludes
the app from its own tunnel. Both are fixed by owning the integration and
driving `libv2ray` the way `CoreServiceManager` does.

### D5. The Hysteria2 client cannot be Xray's

Since the server is now the reference implementation with real Salamander, the
client must speak the real protocol. Xray's is not wire-compatible
(XTLS/Xray-core#5712, closed not-planned), so this engine is a second native
component regardless of what happens to the Xray one.

The candidates are Mihomo, whose `hysteria2.go` is the real protocol and which
is MIT-licensed, or the upstream Hysteria library directly. Mihomo is the
stronger option because it *also* covers XHTTP, REALITY and Vision, so it could
later absorb the Xray engine entirely and leave one core plus the DNS tunnel --
but that is a consequence to reach for later, not a reason to rewrite the
working transports now.

This is why the engine seam matters more than any individual choice of core.
Two protocol families already cannot share one implementation; a third is
coming.

### D6. "Connected" must mean traffic flows

The app reported connected while sending zero packets, for weeks. That is a
safety defect, not a cosmetic one: a user may browse believing they are
protected.

`EngineState` is therefore explicit, and `connected` is not reachable on
optimism:

```
idle -> starting -> handshaking -> connected -> degraded -> stopping -> idle
                         |                          |
                         +--> failed <--------------+
```

- `connected` requires a successful `checkHealth()` -- a real request through
  the tunnel returning an expected result, not a socket that opened.
- `degraded` is entered when health checks begin failing while the interface is
  up, and the UI must show it distinctly from `connected`.
- `failed` carries a cause the UI can render and the log can explain.

Health checking is part of the engine contract because the failure it guards
against is engine-specific.

### D7. The profile contract is engine-agnostic

The API already models protocol, transport and credentials. It gains an
`engine` discriminator and an opaque per-engine parameter bag, so a new family
does not churn the schema:

```
Profile { id, engine, endpoint{ip, port, sni}, credentials, params{...} }
```

`endpoint.ip` rather than a hostname is deliberate -- see D2.

### D8. Supervision and reconnection belong to the service

Engines start and stop; they do not decide policy. `NebulaVpnService` owns
retry with backoff, what happens when the underlying network changes, and
whether a failed engine tears down the interface or holds it. Holding it is the
safer default: tearing it down silently restores unprotected connectivity,
which is the leak the kill switch exists to prevent.

### D9. Observability is a requirement, not a debugging aid

Every engine emits logs at a configurable level, and the level is reachable
from the UI without a rebuild. ADR 0003 took four investigations largely
because the core had never been asked to speak. Per-engine byte counters are
exposed so the UI can show movement rather than a state word.

## What this replaces

`flutter_v2ray_client` is dropped: its two consequential choices -- arming the
legacy dialer, never excluding the app from its own tunnel -- are both wrong
here, and it offers no seam for a second engine. It is a thin wrapper over
`libv2ray`, which is the real dependency.

`badvpn tun2socks` is replaced by `hev-socks5-tunnel` for path B.

## Rejected alternatives

**Mihomo as a single core.** MIT-licensed, and covers XHTTP, REALITY, Vision,
Hysteria2, WireGuard and AmneziaWG in one engine -- it would retire `wg-go`
too. Rejected *now* because it replaces four working transports to fix one
broken one, and it does not do DNS tunnelling, so a second engine is needed
regardless. Once the seam exists it is a swap behind `TunnelEngine`. This ADR
is deliberately structured so that remains true.

**sing-box.** No XHTTP transport, which this deployment depends on.

**Fixing the plugin in place.** The wiring mistakes are in the plugin, but so
is the absence of any engine seam.

**A fixed SOCKS boundary for everything.** Simpler, and this ADR's first draft.
Rejected: it degrades UDP, ICMP and NAT behaviour for every transport in order
to serve composition, which most sessions never use.

## Consequences

WireGuard is adopted into `TunnelEngine` without being rewritten, so the app
has one lifecycle rather than two.

The server is unaffected for existing protocols; this is a client-side change.

DNS tunnelling is the exception, and its server side is not small. CottenDNS's
`cmd/server` is an **authoritative DNS server** and needs:

- **UDP and TCP port 53** on the VPS. Port 53 is currently open and answering,
  so what runs there has to be settled before this lands.
- **An NS delegation** -- a subdomain (say `t.example.org`) delegated to
  the VPS by name server record, so recursive resolvers worldwide forward its
  queries to us. This is a DNS zone change at the registrar or Cloudflare, and
  it is what makes the tunnel reachable from a censored network at all.
- **A shared `encrypt_key.txt`** between server and client, treated as a
  credential: never committed, provisioned like every other secret here.
- `/healthz` and `/metrics` bound to localhost, per upstream guidance.

The delegation is the part with no software workaround and the longest lead
time, so it is worth starting before the client work needs it. Provisioning
per-device DNS-tunnel credentials through the existing API is a separate
question and gets its own ADR; standalone shared-key operation comes first.

`libv2ray` is LGPL-3.0, used as a dynamically linked library, which the licence
permits -- but the app must remain relinkable against a modified build. The
repository currently has no LICENSE file and needs one.

Native cores are per-ABI; APK size and whether to split per ABI must be
revisited once a second core lands.

Every transport is re-verified on a real device after any change to the packet
path or socket exemption. ADR 0003's lesson is binding: provisioning success
and a connected state prove nothing; only counters on the server do.

## Sequencing

The Hysteria2 server is already done and is not listed here.

1. **Per-device Hysteria2 credentials.** The `auth.userpass` map currently holds
   one hand-written test entry. The agent renders it from the database, mirroring
   the Xray client list. Until this lands, Hysteria2 is operator-only.
2. **Replace the plugin.** Our own `VpnService`, self-exclusion, no legacy
   protector, path A. Verify the four Xray transports with server-side counters.
   This fixes the app's silence but *not* Hysteria2, which is no longer an Xray
   transport.
3. **Introduce `TunnelEngine`**, move Xray behind it, add the state machine and
   health checks. No behaviour change; this is the seam.
4. **Add `Hysteria2Engine`** with a real implementation, and Hysteria2 works end
   to end for the first time.
5. **Add path B** (`hev-socks5-tunnel`) and prove Xray works over it too, so both
   paths are exercised before anything depends on the bridge.
6. **Adopt WireGuard** into the interface.
7. **Stand up the DNS tunnel server**: CottenDNS `cmd/server`, NS delegation,
   shared key. Verify from the target network with the stock desktop client
   before any app work -- if the delegation or port 53 does not work from there,
   nothing built on top will.
8. **Add `DnsTunnelEngine`**: submodule pinned, cross-compiled per ABI, run as a
   subprocess, bridge pointed at `127.0.0.1:18000`. Standalone first.
9. **Enable composition** -- Xray dialling through the DNS tunnel's SOCKS port.
10. **Revisit Mihomo.** If step 4 chose it, the Xray engine may be redundant:
    Mihomo covers XHTTP, REALITY and Vision too, which would leave one proxy core
    plus the DNS tunnel.

Step 1 is small and unblocks real use by anyone but the operator. Steps 2 and 3
are worth doing whether or not DNS tunnelling ever ships.

Step 7 before step 8 is deliberate: the delegation is the only piece with no
software workaround, and proving it with an existing client costs nothing.
