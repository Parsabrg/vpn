# Privacy

What a Nebula VPN server stores about the people who use it, for how long,
and what the apps send where. Written from the code and checked against the
live deployment on 2026-10-17. If something here stops being true, it is a
bug in the software or in this page.

Nebula is self-hosted: whoever runs a Nebula server is the one holding this
data, and the one to ask about it.

## Never collected

- The sites and addresses you visit, and the contents of your traffic. The
  servers' Xray and Hysteria2 keep no connection log; checked on the live
  server: no connection lines at all.
- Your DNS lookups.
- Your IP address. No database table has a column for it.
- Your password (only a slow, salted Argon2id hash of it is stored), and
  one-time sign-in, activation and reset codes (only keyed digests).
- Private keys: your WireGuard key never leaves your device.

## Stored while you have an account

| What | Why |
|---|---|
| Email address, optional username | To sign in, and to send the emails you ask for |
| Password hash (Argon2id) | To check your password |
| Account state, device limit, data allowance, expiry | The limits your account has |
| Each device: the name you see in Devices, its platform (Android, Windows, Linux), the app version, and whether it is revoked | So you can see and revoke your devices |
| Sessions: which device, when it expires, when it was last used | To keep you signed in, and to sign a device out when it is revoked |
| Each device's VPN keys and credentials (WireGuard public key, Xray/Hysteria2 credentials, encrypted) | So the server lets that device connect |
| Traffic counters per device and protocol: bytes received and sent, and when they were last read | Data allowances and the usage you see; amounts only, never where they went |

## Kept for a limited time

| What | How long |
|---|---|
| Sign-in and email events (that a sign-in or email happened, its outcome; no IP address) | 90 days |
| Administrator actions (audit log) | 365 days |
| Server health and housekeeping records | 90 days |
| Encrypted nightly backups of the database (age-encrypted before they leave the server) | 30 days, then deleted by the storage bucket's own rule |

A weekly job deletes what is older than this.

## What the apps send, and where

- **To your Nebula server:** sign-in, your device's registration and keys,
  the server list, and requests for a connection. When signed in, the app
  also asks the server which app version is current.
- **Through the VPN:** everything else your device sends while connected,
  except what you chose to let skip it (split tunnelling, Iranian sites,
  websites you listed). The app never sees its contents.
- **To GitHub:** if "Check for updates" is on, the app asks GitHub's public
  releases page for the newest version. GitHub sees your IP address, as for
  any download.
- **To public DNS resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9
  9.9.9.9):** before a connection through Cloudflare, one lookup of
  `cloudflare-ech.com`, which every Cloudflare encrypted connection makes.
  It names no site you visit.
- **Subscriptions and links you add:** fetched from the address you gave;
  they stay on your device and are never sent to your Nebula server.
- **Nothing else.** No analytics, no crash reporting, no advertising, no
  third-party SDKs. The app contains no Google Play Services or Firebase
  code (the QR scanner is open-source ZXing).

On the device, the app keeps your session, settings and the links you added,
in the platform's secure storage where they are secrets.

## Your choices

- See and revoke your devices under Devices.
- Turn off "Check for updates" in Settings.
- To have your account and its data deleted, ask the person who runs your
  server. A delete-my-account button in the app is planned (roadmap,
  section 59); until then an administrator removes it, and backups holding
  it expire within 30 days.

## A server's operator

Running a VPN means your traffic leaves the internet from that server, so
the person running it is in a position of trust. Nebula is built so that
the software records as little as possible, but it cannot stop an operator
from changing what their own server does. Use a server run by someone you
trust, or run your own.
