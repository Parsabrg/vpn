# Edge relay

A Cloudflare Worker that carries VLESS over WebSocket, for people who use
the Nebula app without a Nebula server. It has no accounts and no storage:
one shared UUID admits every copy of the app, and nothing is logged.

Written from the VLESS protocol description. No code from edgetunnel,
BPB-Worker-Panel or any other relay is used.

## What it carries

- TCP to any address or name, IPv4 and IPv6.
- DNS: a UDP stream to port 53 is passed to the same resolver's TCP port,
  whose framing is identical.
- Nothing else over UDP. A Worker has no UDP; QUIC falls back to TCP.

## What a Worker cannot do

- **Reach sites that are on Cloudflare themselves.** Workers may not open
  sockets to Cloudflare's own addresses. Set `RELAY` (`host` or
  `host:port`) to a machine that forwards to Cloudflare, and a stream that
  got no answer is tried once more through it. Without `RELAY` those sites
  do not load.
- **Serve more than the plan allows.** On the free plan an account gets
  100,000 requests a day, reset at midnight UTC, after which Cloudflare
  answers with error 1027. Every stream a client opens is one request, and
  a person opens thousands a day, so one free account serves tens of people,
  not hundreds. The paid plan has no daily limit.

## Reaching it

Some networks filter `workers.dev` by the name in the TLS hello: the
connection comes up, carries a few messages and stalls. The app writes the
hello in pieces for such a name, which got through when measured from Iran
(2026-10-02). A client
that does not will see the relay work for a moment and then hang, which
looks like a fault in the relay and is not. A custom domain on the Worker
avoids the filter altogether.

## Before deploying

Cloudflare's Self-Serve Subscription Agreement, section 2.2.1(j), forbids
using the service "to provide a virtual private network or other similar
proxy services". An account that runs this can be suspended. Do not deploy
it to an account that anything else depends on.

## Deploying

```
npx wrangler login
npx wrangler secret put UUID     # the UUID the app is built with
npx wrangler secret put RELAY    # optional
npx wrangler deploy
```

The address and UUID are deployment values: they go into the app at build
time and are never committed.

## Rotating the UUID

Anyone who unpacks a build can read its UUID and use the relay, so treat it
as public once a build is out. `UUID` takes a comma-separated list: build
each release with a new UUID, add it to the front of the list, and drop the
oldest once the builds that carry it are no longer supported.

```
npx wrangler secret put UUID     # <new uuid>,<previous uuid>
```

## Testing

```
npm test                         # the header reader
npx wrangler dev --var UUID:<uuid>
```

With `wrangler dev` running, an Xray client whose outbound is VLESS over
WebSocket to `127.0.0.1:8787` with that UUID reaches the internet through
it.
