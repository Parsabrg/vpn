# Uptime monitor

A Cloudflare Worker that checks Nebula from outside the VPS (roadmap 44)
every 15 minutes: the CDN route and the Vercel front, the two ways the app
reaches the API. Up means the API itself answered an unauthenticated call
with its JSON 401; a timeout, a TLS or DNS failure, or a front's error page
is down. It sends nothing about users and stores nothing.

While anything is down, each run emails one plain-text alert to `ALERT_TO`
through Cloudflare Email Routing. Turn Email Routing on for the zone and
verify the recipient there first (the Worker can only mail verified
addresses). The address is a secret, not in this file.

Cloudflare cannot see Iran's filtering, so "up" here means the server and
its fronts work, not that they are reachable from inside Iran.

```sh
npx wrangler login
npx wrangler secret put ALERT_TO
npx wrangler deploy
npm test
```
