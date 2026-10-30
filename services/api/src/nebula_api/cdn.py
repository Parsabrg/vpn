"""The Cloudflare route, for when the server's own address is blocked.

A client that cannot reach the server directly reaches the API through a
Cloudflare-proxied hostname instead (`NEBULA_CDN_HOST`). More than one, from
different CDNs, may be listed comma-separated: a network that throttles one
provider's names often leaves another's alone, and the tunnel is pointed back
through whichever one the client arrived by. `NEBULA_FRONT_HOSTS` does the
same for a web host such as Vercel or Netlify, which carries XHTTP only.

When a web host is configured, XHTTP goes through it on every route, and
only WebSocket and gRPC through Cloudflare. Measured from Iran on
2026-10-21 (home line): `cloudflare-ech.com`, the outer name every
Cloudflare ECH hello carries, got no answer at all, so the Cloudflare route
carried nothing with ECH, without it, or with the hello split; XHTTP through
the Vercel front carried 6 of 6 fresh connections, 28.8 Mbit/s down and 23.4
up. WebSocket and gRPC stay on Cloudflare for networks where ECH still works,
and the app tries each protocol in turn.

A tunnel through Cloudflare is handed `NEBULA_CDN_ECH` too: measured from
Iran on 2026-10-07 (home line and Hamrah-e-Avval), WebSocket, XHTTP and gRPC
through Cloudflare carried nothing over HTTPS without Encrypted Client Hello
and everything with it. The value is Xray's `echConfigList`, a setting rather
than code so the resolver it is fetched through can change without a release. Arriving that way is
itself the evidence that the direct route does not work for this client, so
the tunnel endpoints it is handed go through Cloudflare too.

WebSocket, XHTTP and gRPC cross it. Hysteria2 is QUIC over UDP and raw
TCP+TLS is not HTTP at all, so neither can.

gRPC was briefly withdrawn. Routed Cloudflare -> nginx -> xray it carried
5.3 KB up and 0 B down while the app showed "Protected". The same xray gRPC
shape, reached by Cloudflare *directly*, carried traffic end to end. So
gRPC now skips nginx: a second Cloudflare Origin Rule sends the CDN
hostname's /grpc/ paths straight to the inbound's own port (8447), whose
certificate covers the CDN name. See
infrastructure/nginx/README.md, "The Cloudflare backup route".

On the server, the CDN hostname's /ws and /xhttp go through nginx and /grpc/
goes straight to xray, in every case to the same inbounds the direct route
uses, so credentials, paths and service names are unchanged; only the host,
port and TLS name differ.
"""

from typing import NamedTuple

from fastapi import Request

from nebula_api.settings import Settings

CDN_TRANSPORTS = frozenset({"websocket", "grpc", "xhttp"})
# A web host (Vercel, Netlify) forwards ordinary HTTP requests and nothing
# else: no WebSocket upgrade, no gRPC. XHTTP was made for exactly that.
FRONT_TRANSPORTS = frozenset({"xhttp"})
CDN_PORT = 443


class CdnRoute(NamedTuple):
    host: str
    transports: frozenset[str]
    # Xray's echConfigList for a tunnel through this route, or None.
    ech: str | None = None
    # A web host that carries XHTTP instead of this route; see above.
    front: str | None = None

    def tunnel(self, transport: str | None) -> tuple[str, str | None] | None:
        """Where a tunnel of [transport] goes on this route: (host, ECH), or
        None for the direct address."""

        if self.front and transport in FRONT_TRANSPORTS:
            return (self.front, None)
        return (self.host, self.ech) if transport in self.transports else None


def _names(value: str) -> set[str]:
    return {name.strip().lower() for name in value.split(",") if name.strip()}


def cdn_route_for(request: Request) -> CdnRoute | None:
    """The CDN or web-host name this request arrived through; the first CDN
    for a direct arrival when one is configured; else None.

    A CDN keeps its own name in `Host`. A web host's rewrite sends this
    server's name there instead and its own in `X-Forwarded-Host`, so both
    are read. Believing a forged header costs nothing: only configured names
    match, and all the sender gets is a tunnel pointed at one of them.
    """

    settings: Settings = request.app.state.settings
    cdns, fronts = _names(settings.cdn_host), _names(settings.front_hosts)
    ech = settings.cdn_ech.strip() or None
    # The one the client arrived by if that was a web host, else the first.
    front = min(fronts) if fronts else None
    arrived = [
        request.headers.get("host", ""),
        *request.headers.get("x-forwarded-host", "").split(","),
    ]
    for name in (entry.rsplit(":", 1)[0].strip().lower() for entry in arrived):
        if name in cdns:
            return CdnRoute(name, CDN_TRANSPORTS, ech, front)
        if name in fronts:
            # WebSocket and gRPC cannot cross a web host; they take the CDN.
            if cdns:
                return CdnRoute(min(cdns), CDN_TRANSPORTS, ech, name)
            return CdnRoute(name, FRONT_TRANSPORTS)
    # Arriving directly proves only that the API answers there. The direct
    # address carried the API's small requests while every tunnel through it
    # stalled after its first exchange: Xray logged `api...:8448` for a
    # phone showing "Protected" over nothing, where the same credential
    # through Cloudflare loaded every page (2026-10-14). So with a CDN
    # configured, every tunnel that can cross it does.
    if cdns:
        return CdnRoute(min(cdns), CDN_TRANSPORTS, ech, front)
    if front:
        return CdnRoute(front, FRONT_TRANSPORTS)
    return None
