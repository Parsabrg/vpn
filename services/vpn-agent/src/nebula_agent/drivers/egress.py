"""Where a tunnelled client's traffic must never be allowed to go.

Both transports dial on the client's behalf *from this host*: Xray through
its `freedom` outbound, Hysteria2 through its built-in `direct` one. Without
a rule saying otherwise, "the internet" therefore includes everything this
machine can reach locally, and anyone holding a client credential can reach
it through the tunnel:

- this host's loopback: the control-plane API and the admin panel published
  there by Docker, Xray's own HandlerService (which can add users and whole
  inbounds and has no authentication of its own), Hysteria2's traffic-stats
  and kick endpoint, and any unrelated service the operator runs
- the Docker networks carrying PostgreSQL and Redis
- the WireGuard subnet, which is other users
- the cloud provider's metadata service on 169.254.169.254

These ranges are the one policy both transports render from, so a range
added here is refused by both rather than by whichever was remembered.

Explicit ranges rather than Xray's `geoip:private`, deliberately: that form
needs geoip.dat present next to the binary, and a rule referencing a missing
geo file fails config load outright -- taking every transport down rather
than degrading. The client config already avoids `geosite:` for the same
reason (apps/mobile/lib/core/xray/xray_config.dart).

This is the transports' own enforcement. It is not the only layer: the host
firewall refuses the same destinations to these services' users, which is
what still holds if a config is ever rendered without these rules. See
docs/runbooks/production-readiness-audit.md.
"""

BLOCKED_DESTINATIONS: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",  # carrier-grade NAT
    "127.0.0.0/8",
    "169.254.0.0/16",  # link-local, and the cloud metadata service
    "172.16.0.0/12",  # includes this deployment's Docker networks
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",  # benchmarking range, routable-looking but not routed
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

# Resolvers for turning a hostname into an address before matching it
# against the ranges above -- without which a name pointing at a local
# address would be dialled without ever being compared to them. Used by the
# Xray renderer; the Hysteria2 one already carries a resolver of its own.
#
# Public, not the host's own resolver: on this distribution /etc/resolv.conf
# points at systemd-resolved on 127.0.0.53, which is exactly what the
# firewall layer refuses these services.
RESOLVERS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
