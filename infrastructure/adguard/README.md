# Nebula's own resolver (roadmap 26)

AdGuard Home answers the DNS of tunnelled Xray clients, so their lookups no
longer go to a public resolver chosen by the app. It filters nothing (the
ad-blocking profiles keep AdGuard's public filtering resolver, chosen by the
app), keeps no query log and no statistics, and asks its upstreams over
DNS-over-HTTPS, so the hosting network sees neither the names nor the
answers.

## How a lookup gets here

1. The API hands every Xray client `client_dns: ["198.18.0.53"]`
   (`NEBULA_XRAY_CLIENT_DNS`). That address is reserved (RFC 2544 benchmark
   range) and routes nowhere on the internet.
2. The app puts it in the tunnel's DNS settings; Android sends every app's
   lookups there, through the tunnel.
3. The agent renders one Xray rule ahead of the private-address block:
   `198.18.0.53` port 53 goes to a `freedom` outbound that redirects to
   `127.0.0.1:5354` (`NEBULA_XRAY_DNS_REDIRECT=198.18.0.53=127.0.0.1:5354`).
   Nothing else can use that outbound: it only ever dials the resolver.
4. Docker publishes the container's port 5353 on `127.0.0.1:5354`, loopback
   only.

Hysteria2 runs outside Xray, so the API gives its clients no `client_dns`
and they keep the app's default.

## Deploying

```sh
sudo install -d -m 700 /etc/nebula/adguard/conf /var/lib/nebula/adguard/work
sudo install -m 600 infrastructure/adguard/AdGuardHome.yaml /etc/nebula/adguard/conf/
# compose.env:  NEBULA_XRAY_CLIENT_DNS=198.18.0.53
# agent.env:    NEBULA_XRAY_DNS_REDIRECT=198.18.0.53=127.0.0.1:5354
docker compose -p nebula-production --env-file /etc/nebula/compose.env -f production.yaml up -d dns
docker compose -p nebula-production --env-file /etc/nebula/compose.env -f production.yaml up -d --force-recreate --no-deps api
sudo systemctl restart nebula-vpn-agent
```

### The host firewall

`/etc/ufw/before.rules` rejects every new connection the `nebula-xray`
user opens to this host or a local network (see deployment.md, "Host
firewall for the transports"). The resolver needs exactly one exception,
**above** those rejects:

```
-A ufw-before-output -m owner --uid-owner nebula-xray -d 127.0.0.1/32 -p udp --dport 5354 -j ACCEPT
-A ufw-before-output -m owner --uid-owner nebula-xray -d 127.0.0.1/32 -p tcp --dport 5354 -j ACCEPT
```

then `sudo ufw reload`. Without it the redirect is refused and every lookup
through the tunnel fails.

## The admin page

There is none to reach: the container's page is not published on the host,
and the configuration has no users. Settings are changed in
`AdGuardHome.yaml` and the container restarted.

## Checking it

```sh
dig @127.0.0.1 -p 5354 example.com +short          # answers
sudo -u nebula-xray dig @127.0.0.1 -p 5354 example.com +short   # answers (the exception)
docker logs nebula-production-dns-1 | tail          # no query lines
```

On a phone, Settings > Diagnostics > Leak test shows the resolver network
as Quad9 or Cloudflare (the upstreams), not the phone's ISP.
