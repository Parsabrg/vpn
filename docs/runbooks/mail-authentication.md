# Mail authentication

Every account here is reached by email: the activation code, the password
reset. If that mail lands in spam the account is unreachable, and the person
has no other route in.

## Current state

| Mechanism | Where | Status |
|---|---|---|
| From address | `no-reply@example.org` | — |
| SPF | `send.example.org` TXT | `v=spf1 include:amazonses.com ~all` |
| DKIM | `resend._domainkey.example.org` TXT | present |
| DMARC | `_dmarc.example.org` TXT | `v=DMARC1; p=quarantine; adkim=r; aspf=r` (checked 2026-10-21) |
| SPF (root) | `example.org` TXT | `v=spf1 include:_spf.mx.cloudflare.net ~all` (Email Routing, 2026-10-20) |
| DKIM (Cloudflare) | `cf2024-1._domainkey.example.org` TXT | present; signs the uptime monitor's alerts |

SPF sits on `send.` because that is the envelope (return-path) domain Resend
uses, which is correct and not a misconfiguration — it was misread as one once.

DMARC is evaluated against the **From** domain, `example.org`, so that is
where the record belongs.

## Why it matters here

Gmail has required DMARC from bulk senders since February 2024, and treats its
absence as a negative signal for everyone else. Without it, mail from this
system is more likely to be filtered — and a filtered activation code is an
account nobody can get into.

## The record to publish

In Cloudflare, on zone `example.org`:

```
Type     TXT
Name     _dmarc
Content  v=DMARC1; p=none; rua=mailto:<address>
Proxy    DNS only (TXT records are never proxied)
```

`p=none` publishes a policy and asks for reports without changing how any
receiver treats the mail. That is the right starting point even though
alignment already looks correct — the reports are how you confirm that before
tightening.

On `rua`: an address **on this domain** needs no further setup. An address on
any other domain (a personal Gmail, say) requires an authorising record at that
domain, which is not worth the trouble. Omit `rua` entirely if there is nowhere
convenient to receive reports; the policy is still valid and still helps
delivery, you just get no visibility.

## Alignment, before tightening the policy

DMARC passes if **either** SPF or DKIM aligns with the From domain.

- **DKIM aligns exactly.** The key is published at
  `resend._domainkey.example.org`, so it signs as the same domain the mail
  claims to be from. This leg passes under both relaxed and strict alignment.
- **SPF aligns loosely.** The envelope domain is `send.example.org`, a
  subdomain of the From domain, which satisfies relaxed alignment — DMARC's
  default — but would fail under `aspf=s`.

So do not set `aspf=s` without moving SPF, and do not go to `p=quarantine` or
`p=reject` until reports confirm real mail is passing. Tightening a policy that
does not actually align is how a system stops delivering its own account
recovery.

## Checking it took effect

```
nslookup -type=TXT _dmarc.example.org 8.8.8.8
```

## What "delivered" means in our own records

`email_deliveries` records what the Resend API accepted, not what reached an
inbox. A row marked delivered is consistent with the message sitting in a spam
folder, or being dropped after acceptance. Treat it as "we handed it over",
never as proof of receipt — a user reporting a missing code is not contradicted
by that row.
