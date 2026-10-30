# WireGuard: blocked on the path, and one server gap

WireGuard does not pass traffic from the target network. Three real faults were
found and fixed on 2026-09-03. What remained was settled on 2026-09-16: the
handset sends every handshake attempt, and the network between it and the
server drops all but the first. See "Settled" below.

## Fixed

**The interface had no private key.** `wg syncconf` applies its file as the
whole device configuration -- it does not merge. The rendered config was
`[Peer]`-only by design, so every provision and revoke silently stripped the
interface's own key and listen port. `wg show wg1` reported no public key at
all, which means no handshake could ever complete. Every rendered config now
carries `[Interface]`, including the empty-peer case.

**The listen port was random.** Same cause. The interface landed on a different
high port after each apply (32779, 55024, 32121 observed), none of which was
open in the firewall, while clients were correctly told 51821.

**A device could connect exactly once.** `uq_wireguard_peers_public_key` spanned
every row including revoked ones. A client keeps its keypair, so reconnecting
presents the same public key and the insert failed on a constraint the client
could not satisfy without discarding its identity. Now scoped to live peers,
matching every other uniqueness rule on that table.

After these, the server is demonstrably correct: key present and matching what
clients were issued, port 51821, firewalled, peers loaded.

## Settled: the network drops it, not the device

What was measured on 2026-09-03:

- The phone logs `Sending handshake initiation` every 5 seconds, continuously.
- A 20-second capture on UDP/51821 saw zero packets, and the peer's transfer
  counter stayed at 148 B received / 92 B sent -- one initiation and one
  response, never repeated.

That left open whether the retries ever left the handset, with v2rayNG's VPN
running at the same time as a confound. Retested on 2026-09-16 with v2rayNG
force-stopped, so no other VPN existed:

- **Server, 60-second capture:** one inbound packet and one reply, the same
  148 B / 92 B pair. The handshake never completed.
- **Handset, `/proc/net/dev` sampled every 5 seconds:** `wlan0` transmitted
  exactly one packet of 190 bytes per interval -- a 148-byte WireGuard
  initiation plus 8 bytes of UDP, 20 of IPv4 and 14 of Ethernet. Everything
  else on the phone was going into `tun0`. `wlan0` never received the 134-byte
  reply.

So the retries leave the phone over Wi-Fi and do not reach the server; the
first packet does, and its reply does not come back. That is the shape of a
flow blocked after its first packet, somewhere between the home network and
the server. The earlier note that the retries "are not reaching the wire" was
wrong. The same server's other WireGuard interface (`wg0`, port 51820) has not
completed a handshake in 49 days either.

Established on 2026-09-17: it is not the home router. The same test on the
phone's mobile data, a different carrier with the home Wi-Fi switched off, gave
the same shape. A server capture saw exactly one 148-byte initiation and sent
the 92-byte reply within 0.3 ms. The phone sent two further initiations over the
next 13 seconds, and none of them reached the server. Two unrelated Iranian
networks drop the flow after its first packet, which is what recognising
WireGuard's handshake and blocking it looks like. Nothing on the server changes
that; a WireGuard that works here needs its traffic disguised, which plain
WireGuard does not do.

### What the app does about it

It used to show "Protected" as soon as the interface existed, over a tunnel
that carried nothing, so every app on the phone stopped working with no
explanation. It now waits for a completed handshake -- 15 seconds, three
attempts -- and if none comes, stops the tunnel, releases the peer on the
server and says the network may be blocking WireGuard.

## Server gap: `wg1` traffic is not allowed to leave (fixed 2026-09-17)

`install.sh` does this itself since 2026-10-30, for every new or rerun
install: IPv4 forwarding in `/etc/sysctl.d/99-nebula-forward.conf`, the
masquerade for the server's WireGuard range (`10.77.0.0/20` on a new install,
kept as it is on an older one; see `docs/environment.md`) and the client restrictions (not each other,
not this host, not private, Docker or metadata ranges) in ufw's
`before.rules` under a `nebula-wireguard` marker, and
`ufw route allow in on wg0 out on <outgoing interface>`. The steps below are
how the first server was fixed by hand, before that.

Found in the same session, and independent of the block: on a network that
does let WireGuard through, the handshake would complete and traffic would
still go nowhere. The rules below were applied on 2026-09-17 and checked
afterwards: `ufw-user-forward` accepts `wg1` to `eth0`, one masquerade rule for
`10.77.0.0/24` is loaded, and `wg1.conf` carries the `PostUp`/`PostDown` lines
so it survives a reboot.

- ufw's default for routed traffic is `deny (routed)`, so `FORWARD` drops.
- `wg0.conf` adds its own `FORWARD` accepts in `PostUp`. `wg1.conf` -- Nebula's
  interface -- has no `PostUp` at all, and no rule anywhere accepts `wg1`.
- NAT works only by accident: `wg0`'s `PostUp` adds a masquerade for everything
  leaving `eth0`. Take `wg0` down and `wg1` loses it too.

The fix, for whoever operates the host. It adds rules and removes nothing:

```bash
ufw route allow in on wg1 out on eth0 comment 'nebula wireguard egress'
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE
```

Return traffic is already accepted by ufw's own `RELATED,ESTABLISHED` rule. The
`ufw route` rule persists; the masquerade does not, so also add to the
`[Interface]` section of `/etc/wireguard/wg1.conf`:

```ini
PostUp = iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE
```

**Confirmed across a reboot on 2026-09-21.** The host was rebooted for a kernel
upgrade after these were applied, which is the event that would have quietly
undone the masquerade if the `PostUp` line had not been added. All four checks
pass afterwards: the `ufw route` rule is present, the `POSTROUTING` masquerade
for `10.77.0.0/24` is loaded, `wg1.conf` still carries `PostUp`, and `wg1` is up
on 51821 with its key. So this section needs no action on the next reboot
either -- it is persistence that has now actually been observed rather than
inferred from the config.

## Not a route out of this

Xray-core supports WireGuard as an **outbound** only -- it dials out to a
WireGuard server, it cannot serve WireGuard clients. Mihomo is the same. So
moving WireGuard onto a proxy core is not available server-side; the kernel
implementation stays either way. Consolidating the *client* side is possible
later and is covered by ADR 0004.
