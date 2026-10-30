# Monitoring: what watches, and what it cannot see

Before this existed, nothing in the deployment reported a fault. Every problem
was found by a person noticing, usually late:

- A bad config restarted Hysteria2 **25,126 times** while `systemctl is-active`
  reported `active` throughout.
- XHTTP advertised a loopback endpoint from the day it was written. It surfaced
  as a user saying "connects but no data".
- A TLS certificate expired.
- CI was red for five commits and nothing said so.

Four mechanisms now cover it, and they are complementary rather than
redundant: one catches a unit failing, one catches the faults that produce no
failure event, one catches the host being gone entirely, and one catches the
server becoming unreachable from the country its users are in.

## `OnFailure=` — a unit entered `failed`

`nebula-alert@.service` is a template. Any unit carrying
`OnFailure=nebula-alert@%n.service` sends one email when it fails, with the
last 20 journal lines in the body. `%n` is the failing unit's name, so one
template serves every unit.

Wired into `nebula-reconcile`, `nebula-backup`, `nebula-xray`,
`nebula-hysteria`, `nebula-compose`, and `nebula-vpn-agent`.

**What it cannot catch**, and why the health check exists:

- **A crash loop never reaches `failed`.** The start-rate limit on
  `nebula-xray` and `nebula-hysteria` is deliberately huge, because restarts
  are also how config is applied — a smaller ceiling already cost real work
  (a sweep of seven revokes landed five). So a unit restarting every fifteen
  seconds forever never trips the limit and never enters a failed state.
- **A timer that stops firing produces no event at all.** The absence is the
  fault. Only something asking can see it.
- **A certificate expiring is not a unit failure** either.

## `nebula-healthcheck.timer` — asking the questions

Runs every 20 minutes, and 5 minutes after boot. Checks:

| Check | Catches |
|---|---|
| `nebula-reconcile.timer` fired in the last hour | revocation silently stopping |
| `nebula-backup.timer` fired in the last 36 hours | backups silently stopping |
| the three units are `active` | a unit down without failing |
| restart counters do not move across a 20s sample | a crash loop |
| every advertised endpoint answers | the XHTTP class of fault |
| TLS certificate has more than 14 days left | renewal that has been failing |
| the `usage` container is running and not unhealthy | allowances and lapsed access no longer enforced within seconds |

The reconcile check is the one that matters most, and it is new in kind rather
than degree. Revoking a device now marks its credentials `REVOKING` and hands
them to that timer to remove from the server — that hand-off is what bounds
revocation at about 17 minutes. **If the timer quietly stops, revocations stop
completing and access continues indefinitely, while every screen shows the
device as revoked.** A background repair job became a load-bearing security
control, so it needs a dead man's switch.

Traffic allowances are enforced by the `usage` container, every fifteen
seconds: it reads usage, cuts off an account that has spent its allowance or
whose access has lapsed, and takes its credentials off the servers in the same
pass. The reconcile sweep runs a single pass as well, and that copy is the one
that alerts, so if the container stops, allowances are still enforced -- every
fifteen minutes, which let a spent 30 MB account carry on for twenty. The
container reads `unhealthy` in `docker ps` once no pass has finished for two
minutes, and the health check below emails when it is unhealthy, not running,
or gone.

The container replaced `nebula-usage.timer`, which ran the same pass once a
minute. On a host that still has the timer:

```shell
systemctl disable --now nebula-usage.timer
rm /etc/systemd/system/nebula-usage.service /etc/systemd/system/nebula-usage.timer
systemctl daemon-reload
```

Run it by hand any time:

```shell
/opt/nebula-vpn-agent/.venv/bin/nebula-agent-healthcheck
```

It prints every problem and exits non-zero if it had something to report and
nowhere to send it.

## When it emails, and when it does not

- A **new** problem, or a change to the set of problems: immediately.
- The **same** problem, unchanged: once a day, not every 20 minutes. A mailbox
  that receives the same alert 72 times a day gets filtered within a week, at
  which point this is worse than no monitoring because it still looks like
  monitoring.
- **Recovery**: once, when everything passes again. "It is fixed" is the other
  half of an alert; without it the only way to learn is to go and look, which
  is the habit this exists to remove.

State lives in `/var/lib/nebula/healthcheck.state`. It is under `/var/lib`
rather than `/run` deliberately — `/run` is tmpfs, and losing this on every
boot would re-send every standing problem at boot.

If the health check itself fails — it could not reach Resend, or a binary it
needs is missing — it exits non-zero and trips its own `OnFailure=`. A monitor
that breaks silently is indistinguishable from a healthy system.

## Configuring it

In `/etc/nebula/agent.env`:

```
NEBULA_ALERT_RECIPIENT=you@example.org
NEBULA_ALERT_API_KEY_FILE=/etc/nebula/secrets/resend_api_key
NEBULA_ALERT_HOSTNAME=vpn1
```

Mail goes through Resend, the same provider the app already uses, so SPF and
DKIM for this domain are already correct and the mail is unlikely to be
filtered. See `mail-authentication.md` — DMARC is still missing, and that is
worth fixing for alerts as much as for account mail.

Alerting is opt-in. Without a recipient every check still runs and prints, and
the command fails loudly rather than pretending it reported something.

**The alerter deliberately shares nothing with what it monitors.** It runs on
the host, not in a container, and POSTs to Resend with nothing but the standard
library. An alerter that needed the API container up could not tell you the API
container was down, which is the message most worth receiving.

## Installing

```shell
cp infrastructure/systemd/nebula-alert@.service /etc/systemd/system/
cp infrastructure/systemd/nebula-healthcheck.service /etc/systemd/system/
cp infrastructure/systemd/nebula-healthcheck.timer /etc/systemd/system/
# and the OnFailure= lines on the existing units
cp infrastructure/systemd/nebula-*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nebula-healthcheck.timer
```

Verify it end to end before trusting it, because an alerting path that has
never delivered a message is an assumption rather than a control:

```shell
systemctl start nebula-alert@nebula-xray.service.service
journalctl -u nebula-alert@nebula-xray.service.service -n 20 --no-pager
```

The doubled `.service` is correct, not a typo: `%n` expands to the full unit
name including its suffix, so the instance of `nebula-alert@.service` for
`nebula-xray.service` is `nebula-alert@nebula-xray.service.service`.

That sends a real email about a unit that did not actually fail. If it does not
arrive, fix that now rather than discovering it during the first real outage.

## The external dead man's switch

Everything above reports *from* the VPS, which means none of it can report the
VPS being gone. Power loss, a network partition, a kernel panic, the host
suspended over an unpaid invoice: in each of those the alerter dies with the
thing it was watching, and the result is silence that looks exactly like
health. Silence is the one failure a self-hosted monitor cannot report.

The only shape that covers it is an outside service expecting to hear from us
on a schedule, so that the alert is generated by the **absence** of a message.

The health check pings it on every run:

| Outcome | What is sent | What the service does |
|---|---|---|
| all checks pass | `GET <url>` | resets its timer, stays quiet |
| problems found | `GET <url>/fail` | alerts immediately |
| host is dead, or the timer stopped | nothing | alerts when the period elapses |

The failure ping duplicates the email deliberately. The case worth covering is
Resend being down, the API key being wrong, or the mail landing in spam --
exactly when the primary path is the thing that is broken.

Three properties, each with a test, because each is a way this could quietly
stop working:

- **It pings before the email is attempted**, so a broken mail path cannot
  prevent it.
- **It pings even when the email is de-duplicated away.** Emails repeat only
  once a day while a problem stands; the ping must not sit behind that, since
  a host with a standing problem is exactly when it might die.
- **It never raises.** The caller is in the middle of reporting real problems,
  and failing it over an unreachable monitoring service would suppress the
  alert that mattered. It needs no error path of its own either: if these
  pings stop arriving, the external service says so.

### Setting it up

The account has to be yours -- I cannot create one.

1. Sign up at <https://healthchecks.io> (free tier is enough; any service
   offering a periodic ping URL works the same way).
2. Create a check with **period 30 minutes** and **grace 20 minutes**. The
   health check runs every 20, so 30 tolerates one missed run and the grace
   covers the timer's randomised delay. Tighter than that will page you for a
   reboot.
3. Copy its ping URL into `/etc/nebula/agent.env`:

   ```
   NEBULA_DEADMAN_URL=https://hc-ping.com/<uuid>
   ```

4. `systemctl restart nebula-healthcheck.service` and confirm the dashboard
   shows the check as up.
5. Then verify the thing that actually matters, which is that it alerts when
   pings stop. An untested dead man's switch is an assumption, and this one is
   only ever exercised on the day the host dies.

   At the real settings that means waiting 50 minutes. Shortening the window
   for the test costs nothing and exercises the identical path:

   1. `systemctl stop nebula-healthcheck.timer` -- no more pings.
   2. On the dashboard, set period and grace to **1 minute** each.
   3. Within about two minutes the check goes amber (late), then red (down),
      and the email arrives.
   4. Set period and grace back to **30** and **20 minutes**.
   5. `systemctl start nebula-healthcheck.timer`, then
      `systemctl start nebula-healthcheck.service` to ping immediately.
      The check returns to green.

   Done on 2026-09-04 and it behaved exactly so: green, amber, red with the
   alert, then green again on the first ping back.

**Treat the ping URL as a secret.** It is a capability: anyone holding it can
keep the switch alive while the host is dead, which is worse than not having
one. It is never logged, and failures deliberately do not print it.

The ping carries no body and no query parameters -- only that this host is
alive. There is no reason to hand a third party anything else.

### What it costs

The VPS makes an outbound HTTPS request to the monitoring provider every 20
minutes, which tells that provider this IP exists and is running something
being monitored. For a censorship-circumvention host that is worth naming,
though it is a small addition to what Hetzner, Cloudflare, Let's Encrypt and
Resend already know. Self-hosting the receiving end on a second machine avoids
it, and is the better answer if one is ever available.

## The probe from Iran

`nebula-reachability.timer`, hourly. Every other check runs on the VPS and
answers "is this server healthy". A transport can be perfectly served and
completely unusable, and from the server those look identical.

This asks probes inside Iran, via Globalping, which needs no account and has
five probes in Tehran across four networks.

### Read the result correctly

It runs a **TCP traceroute** to each advertised port and asks whether the last
hop is the server's own address.

**What a green result means:** packets reach that port from Iran. It catches
the blocking that is total and common -- the IP null-routed, the port dropped
at the border, DNS answering with something else.

**What a green result does NOT mean:** that the tunnel works. Iranian
filtering increasingly fingerprints the handshake itself, and a VLESS or
REALITY session torn down by DPI looks identical here to a healthy one. This
check does not speak the protocol and cannot.

Two further limits, both real:

- The five probes are all `datacenter-network` -- Iranian hosting providers,
  not the consumer mobile carriers the app's users are on. Those are filtered
  differently, so this is a proxy for a user's experience, not a measurement
  of it.
- Hysteria2 is skipped entirely. It is QUIC over UDP, and a TCP traceroute to
  that port would be a fabricated result rather than a missing one.

So: **only a real client in Iran can tell you a transport works.** This tells
you when one has certainly stopped.

### Why it compares against a control

The first version of this check reported every transport blocked, from
everywhere, permanently. An HTTPS request to a VLESS inbound is correctly
refused by the server, and that refusal was being read as censorship. A
control run from Germany returned the identical result, which is what caught
it before it shipped.

So the verdict requires both halves: unreachable from Iran **and** reachable
elsewhere. Unreachable from everywhere is a server fault, which the health
check already reports and this must not duplicate as a censorship alarm.
Unusable measurement service is a third state again -- it fails the unit and
never sends a blocking alert, because not knowing is not the same as blocked.

Measured on 2026-09-04: 5/5 Iranian probes reached the server on 8445, 8447,
8448 and 8449. The control scored 2-3 of 4, which is traceroute noise from
control probes -- and the reason a blocking verdict needs only one control
probe to succeed rather than all of them.

Run it by hand:

```shell
/opt/nebula-vpn-agent/.venv/bin/nebula-agent-reachability
```

## What is still not covered

- **Nothing watches the containers.** `docker ps` health is visible to a
  person, not to this. The API being down is caught only indirectly, when the
  reconcile timer's runs start failing.
- **Nothing tests the real protocol from Iran.** The reachability check proves
  packets arrive at the port; it cannot see DPI tearing down a VLESS or
  REALITY handshake, which is how Iranian filtering increasingly works. The
  only thing that can is a real client on a real consumer carrier. Having the
  Android app report connection outcomes would close this, and is the obvious
  next step -- it needs a privacy design first, because "which user tried
  which transport and failed" is exactly the data this project should not
  casually collect.
