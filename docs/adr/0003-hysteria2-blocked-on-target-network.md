# ADR 0003: Hysteria2 is shipped but unusable on the target network

- Status: amended -- original diagnosis disproven, see "Correction"
- Date: 2026-09-01 (amended 2026-09-02)

## Context

Hysteria2 is implemented end to end -- an Xray-core `hysteria` inbound the agent
renders and applies, Salamander obfuscation, per-device credentials, an
ad-blocking sibling profile, and client config rendering in the mobile app. It
is selectable in the picker alongside the other transports.

It does not pass traffic from the network this deployment exists to serve, and
after a long investigation that is understood to be outside this codebase.

## What was established

The server side works. An Xray-core client run directly on the VPS, against the
same inbound with the same credentials and obfuscation, moved real traffic in
~177ms. The port answers unrelated internet traffic normally: an unrelated
client held a full working session against the host's separate Hysteria2 setup
while the affected network could not.

Packets from the affected network never arrive. Across every attempt, the
server-side firewall counter for the Hysteria2 port stayed at exactly the
handful of packets from deliberate test probes, while the phone's own tunnel
interface showed bytes leaving. No rejection, no ICMP, no error either end --
traffic is silently dropped somewhere in between.

The failure is not specific to this implementation. A long-standing,
independent Hysteria2 setup on the same host -- the standalone `hysteria`
binary, a different port, a different Salamander implementation, and previously
working -- began failing from the same network on the same day, while
continuing to serve other clients.

## What was ruled out

- **Obfuscation.** Added Xray-core's Salamander (`streamSettings.udpmasks`),
  which is what the previously-working reference setup relied on. No change.
  Note Xray-core's Salamander is not wire-compatible with the standalone
  project's (XTLS/Xray-core#5712, closed not-planned), but both ends here are
  Xray-core, so that is not the issue.
- **The client library.** `flutter_v2ray_client`'s protector callback was
  instrumented and confirmed firing (`onProtect ... result=true`), so the
  outbound socket is correctly exempted from the app's own tunnel. Xray-core's
  hysteria dialer was also confirmed to route through the same
  `protect()`-hookable path as every other transport.
- **The port.** Tested on 8450 and on UDP/443, the latter chosen because it is
  indistinguishable from ordinary QUIC/HTTP-3 and is the case DPI is most
  likely to permit. The inbound verifiably re-rendered onto 443 and provisioned
  a client. No change.
- **The access network.** Fails identically on WiFi and on cellular.
- **The client application.** Fails identically through this app and through
  v2rayNG with a separate, previously-working config.
- **Device-level interference.** The handset's OEM network-acceleration service
  (`com.oplus.nas`, which owns a `vgate0` interface) was disabled for a test.
  No change.

## Decision

Hysteria2 stays implemented, seeded, and selectable, but is documented as
non-functional on the target network and is not counted as a working transport.
No further engineering effort is spent on it until something changes outside
this codebase.

The four TCP-based transports carry the deployment: XHTTP, gRPC, WebSocket, and
raw TCP are all confirmed passing real traffic, with per-port packet counters on
the server as evidence rather than a provisioning success alone. Losing
Hysteria2 costs the resilience of having a QUIC-based option, not availability.

## Consequences

Retesting is cheap if circumstances change -- a different ISP, a different
country, or a shift in filtering. The whole path is in place; it only needs a
network that will carry the packets. UDP/443 is the first thing to retry, since
it is the most permissive case and was only ever tested from one network.

The deployment is left on the default port 8450 so the running configuration
matches this repository rather than carrying an undocumented override.

Corroborating detail worth keeping: the same network was independently observed
injecting forged DNS answers -- returning RFC1918 addresses such as
`10.10.34.36` for public names, and a fabricated `404` for a Google Maven
artifact that resolves and downloads normally through a tunnel. Active
interference on this path is established, not inferred.

## Correction (2026-09-02)

The observations above are accurate. The conclusion drawn from them is not.
The original text is kept intact so the reasoning stays auditable; this
section records what was actually true.

### The network does carry QUIC to this host

Count-only `iptables` rules were placed on UDP/8443 and UDP/8450, and the
same handset connected to each in turn, minutes apart, on the same network
and the same public address:

```
udp dpt:8443    610 packets   201 KB     standalone hysteria, worked
udp dpt:8450      0 packets     0 B      this deployment, "connected", no traffic
```

The counters were validated by sending probes from a third machine and
watching both increment, so the zero is a real measurement rather than a
broken instrument.

"Packets from the affected network never arrive" therefore holds only for
8450. The claim it was used to support -- that this path will not carry
Hysteria2 -- is refuted by 201KB arriving on the neighbouring port.

### The corroborating failure was an expired certificate

The strongest evidence above is that an independent, previously-working
Hysteria2 setup "began failing from the same network on the same day". Two
unrelated systems failing together is good reason to look outside both, and
that inference was sound. It was a coincidence.

That setup pinned `hello.example.org` with `insecure=0`. The
certificate expired at 13:28:43 UTC on 2026-09-01 -- the same day -- and the
hostname has no DNS record, so ACME validation could never have renewed it.
Renewal had in fact been failing twice daily for months, unnoticed, because
certbot was configured for `standalone` mode on a host where nginx already
held port 80. Repointing that setup at a renewable certificate restored it
immediately, and it has served traffic continuously since.

So the two systems did not fail for a shared external reason. One failed
because a certificate lapsed; the other had never worked.

### The port was ruled out, properly this time

The deployment's Hysteria2 inbound was moved onto UDP/8443 -- the exact port
that had just carried 201KB from this handset -- with the standalone
listener stopped to free it. The app provisioned a client successfully and
the inbound restarted to accept it.

Zero packets arrived. A broader count of all UDP to the host, and a packet
capture running while the app retried, both agree: nothing from that handset
reaches this server on any port. The only UDP on the wire during the capture
was the server's own outbound QUIC.

Note the original "the port" section above is weaker than it reads -- UDP/443
was tested during the window when the reference setup was itself broken by the
expired certificate, so it had no working control to compare against.

### The client never transmits

The remaining explanation is the only one left standing, and it is positively
supported rather than merely surviving:

- The configuration is not at fault. The exact JSON the app renders -- same
  shape, same credentials, same obfuscation -- was run through an Xray-core
  client on the server and passed in 85ms, against the public address, the
  hostname, and loopback, with and without obfuscation.
- On the handset the tunnel interface comes up (`tun0`, `26.26.26.1/30`) and
  the app reports "connected", confirming that state reflects
  `VpnService.establish()` succeeding rather than a working tunnel.
- The only thing the Xray process logs is `Using Prepared: <server ip>`, once
  every five seconds, from rotating threads. No startup banner, no dial
  attempt, no error, and no Java exception anywhere in the app's process.

Xray-core normally announces its version on startup. Its complete silence,
combined with a `protect()` callback firing on a timer, is consistent with the
core never starting for this outbound while the surrounding service carries
on -- not with a dial being attempted and dropped.

Two things make that shape plausible. The app's Hysteria2 outbound carries a
`flutter_v2ray_client` workaround -- a redundant `settings.servers` array
added so the library's Java notification parser does not throw -- so
Xray-core is handed a config shape upstream does not exercise. And Xray
26.3.27 has moved Hysteria fields (`up`/`down` -> `finalmask/quicParams`, per
the server's own startup warning) while both the agent and the app still emit
the older shape.

A `log` block was added to the client config (it had none, which is why the
core had been silent), and the rebuilt app produced the answer:

```
I/GoLog: [Warning] core: Xray 26.6.1 started
I/GoLog: Starting core successfully
I/GoLog: from tcp:127.0.0.1:58620 accepted tcp:94.140.14.140:853
I/GoLog: Using Prepared: 203.0.113.10      <- then only this, every 5s
```

Xray-core starts, and the tunnel plumbing works: tun2socks runs and feeds it
real connections. Those connections reach the Hysteria2 outbound and stop
there. On the handset, `/proc/net/udp` shows the app holding UDP sockets whose
`rem_address` is `00000000:0000` -- created and never connected -- and no
socket to the server exists at any point. Xray logs no dial error, and the
`Using Prepared` line (emitted by the library's protected dialer when it
resolves the server address) repeats on a five-second retry loop that never
completes.

The version difference between client and server was checked and cleared:
Xray 26.6.1, the exact build the app ships, was run on the server against the
26.3.27 inbound with the app's exact config and passed in 64ms.

### Conclusion: the client library cannot dial a QUIC outbound

Everything outside the Android client has now been eliminated by measurement
rather than argument -- the network carries the protocol, the port is
irrelevant, the configuration is byte-for-byte correct, and both binaries
interoperate. What remains is `flutter_v2ray_client`'s bundled `libv2ray`:
its protected dialer is invoked for the server address and never produces a
connected UDP socket, so the QUIC handshake is never sent.

This is the risk the original plan flagged and that the feasibility spike
answered too narrowly. The spike asked whether Xray-core supports Hysteria2 --
it does, and the server side proves it. The question that mattered was whether
the *Android wrapper* can dial a UDP transport, and that was never tested
independently of the config.

### Confirmed against a working client on the same handset

v2rayNG 2.2.6 runs Hysteria2 on this exact phone and network, so Android is
not the obstacle. Both apps' native cores were extracted and compared:

|                             | v2rayNG 2.2.6         | this app              |
|-----------------------------|-----------------------|-----------------------|
| built from                  | 2dust/AndroidLibXrayLite | same               |
| bundled core                | xray-core@v1.260327.1 | same                  |
| hysteria / quic-go symbols  | 46 / 34               | identical counts      |
| RegisterDialerController    | present               | present               |
| RegisterListenerController  | present               | present               |
| ProtectedDialer             | ABSENT                | PRESENT               |

The Hysteria2 and QUIC implementations are the same code. The single
difference is the legacy `ProtectedDialer`, which our build still carries and
which the log proves is the active path -- `Using Prepared` is emitted by
exactly that component.

That dialer intercepts the dial to the server and hand-builds a *stream*
connection; it predates any UDP transport. The two `Register*Controller`
hooks both builds carry are its replacement, protecting sockets at creation
regardless of type, with `RegisterListenerController` covering the packet
socket QUIC requires. v2rayNG removed the old dialer and lets those run. Ours
still has it in front, so it captures the server dial before the generic path
can, returns something QUIC cannot use, and retries every five seconds.

TCP transports are unaffected because a stream connection is precisely what
that dialer was built to return -- which is why four transports work and only
the QUIC one does not.

### Client-side fixes attempted and ruled out

Three plausible causes inside our control were tested against the real device.
None moved the packet count off zero, and they are recorded so they are not
tried again:

- **The legacy protected dialer.** `flutter_v2ray_client` calls
  `Libv2ray.setProtectorServer()`, arming a dialer that intercepts the dial to
  the server and hand-builds a stream connection. Not calling it disarmed the
  dialer -- `Using Prepared` disappeared from the log, confirming the change
  took effect -- and the core fell through to its own path. Still zero packets.
- **The app's traffic being captured by its own tunnel.** Nothing called
  `addDisallowedApplication(getPackageName())`, so the core's own socket to the
  server was routed into the interface it was trying to feed. Adding it applied
  cleanly and, importantly, did not regress the four working transports (VLESS
  verified passing traffic afterwards). Still zero packets.
- **A DNS bootstrap deadlock.** With the pre-resolving dialer disarmed, the core
  had to resolve `api.example.org` itself through a DNS config pointing
  into the not-yet-established tunnel. The agent was reconfigured to advertise
  the bare IP with the SNI unchanged, removing any name to resolve. Still zero
  packets.

After all three the core starts, accepts connections from tun2socks, holds ~25
unconnected UDP sockets -- which is normal, quic-go uses an unconnected socket
and `sendto` -- and never puts a datagram on the wire, logging no error at
warning level.

The conclusion is therefore not that a particular call is wrong but that this
`libv2ray` build does not complete a QUIC outbound on Android at all. Nothing
reachable from Dart, from the plugin's Java, or from server configuration
changes that, because the failure is inside a 33MB prebuilt binary.

### Update (2026-09-03): there were two faults, not one

The client-side conclusion above is correct but incomplete. It was reached
without ever testing a *working* client against this deployment's inbound.

v2rayNG -- which carries Hysteria2 on this handset daily against the operator's
own server -- was pointed at Nebula's Xray inbound for the first time. It failed
too, but differently: 56 packets and 73KB reached the port and the session never
established. Two things follow.

**The network does not block this port.** Every earlier port test used the app,
which transmits nothing, so "blocked port" and "silent client" were
indistinguishable. A client that does transmit separates them, and the packets
arrive.

**A second fault exists on the server**, so fixing the client alone would have
left Hysteria2 broken.

### Xray-core silently discards the obfuscation it accepts

Tested against the live inbound:

```
client WITH matching salamander password        PASS
client WITHOUT any obfuscation                  PASS
client WITH a DELIBERATELY WRONG password       PASS   <--
```

A wrong password authenticates. `streamSettings.udpmasks` is accepted by the
config parser and then ignored, so the inbound believed it was obfuscated and
was not -- and a client applying real Salamander cannot talk to it. Same class
of defect the core reports at every startup for its bandwidth fields
(`congestion & up & down & udphop move to finalmask/quicParams`), which the
rendered config still sets and which are likewise ignored.

The earlier server-side test that appeared to prove the inbound healthy ran a
client *on the server*. Both ends were Xray, both ignored the same setting, so
they agreed with each other. It proved the config parsed and the credential was
valid; it never proved the thing worked across a network.

### Resolution: the standalone binary

Hysteria2 now runs on the reference implementation -- the same program already
known to carry Hysteria2 from the same network -- under
`nebula-hysteria.service`, with Xray's inbound disabled and its port freed.
Verified:

```
correct creds, verified cert       PASS
WRONG obfs password                FAIL   <-- correctly rejected
```

Obfuscation is enforced for the first time, and the server is confirmed working
from the handset via v2rayNG. Initial instability was Brutal congestion control
transmitting at a declared 1gbps rather than a measured rate; `ignoreClientBandwidth`
moves it to BBR and it settled.

This is what the original plan specified -- "Hysteria2 is not part of Xray-core
at all, it's the standalone `hysteria` binary" -- before the implementation took
the single-binary shortcut. The shortcut was the fault.

Still open: per-device credentials (the `userpass` map holds one hand-written
test entry and needs rendering from the database), and the client, which still
transmits nothing and now also needs a real Hysteria2 implementation rather than
Xray's.

### Consequences

Hysteria2 needs a different engine on the device, not a different
configuration. Updating to a current AndroidLibXrayLite build was considered
and rejected: its `startLoop(config, tunFd)` hands the TUN descriptor to the
core, collapsing the local-SOCKS boundary this app is built around. Only one
component can own that descriptor, which would foreclose running a second
engine -- DNS tunnelling alongside proxy transports, say -- beside it.

The direction that fixes Hysteria2 without giving that up is a core that
speaks it natively behind the existing SOCKS boundary. Mihomo (Clash.Meta) is
the strongest candidate: it covers Hysteria2, WireGuard and AmneziaWG in one
engine, which would also retire the separate `wg-go` this app carries, and it
is in production use against these networks. That is a native integration
replacing `flutter_v2ray_client`, and should be scoped as its own project.

Until that lands, Hysteria2 should be hidden from the picker rather than
offered and silently failing. It currently reports "connected" while passing
no traffic, which is worse than not offering it at all, and worst for a user
who believes they are protected. The four TCP-based transports are unaffected.

The diagnostic `log` block stays regardless. Every transport shared this blind
spot; a future tunnel failure now leaves evidence instead of silence.
