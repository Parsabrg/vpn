# Nebula VPN — Roadmap sections

The full target adopted 2026-10-01, sections 1–109. What comes next and the
status of each piece are in [ROADMAP.md](ROADMAP.md); the guiding principles
(section 110) are there too.

## 1. Core Architecture

- Move Nebula onto dedicated production infrastructure.
- Run production on a host of its own, with nothing else on it.
- Separate the control plane from VPN exit nodes.
- Keep PostgreSQL, Redis, API, worker and admin panel on the control plane.
- Keep Xray, WireGuard, Hysteria2, DNS and the VPN Agent on VPN nodes.
- Communicate between control plane and VPN nodes only through the narrow mTLS agent API.
- Never give the public API unrestricted SSH access to VPN nodes.
- Never give the API arbitrary shell execution on VPN nodes.
- Keep VPN Agent operations typed and capability-limited.
- Preserve fixed-argv/no-shell execution.
- Keep VPN runtime configuration separate from account/control-plane logic.
- Make existing tunnels independent from temporary control-plane outages where possible.
- Ensure `API down != existing VPN down`.
- Ensure `Admin down != existing VPN down`.
- Ensure `Database down != immediately killing established tunnels`.
- Maintain last-known-good configuration locally on VPN nodes.
- Keep atomic runtime configuration updates and rollback.
- Add a second real VPN node.
- Validate the architecture against multiple nodes rather than only designing for them.
- Add additional regions after two-node behavior is stable.
- Design for horizontal VPN-node scaling.
- Keep the control plane protocol-neutral.
- Keep connection engines modular so new engines can be added without redesigning accounts/devices.

Target architecture:

```
                         USERS / ADMINS
                              │
                              ▼
                    ┌───────────────────┐
                    │   CONTROL PLANE   │
                    │                   │
                    │ API               │
                    │ Admin             │
                    │ PostgreSQL        │
                    │ Redis             │
                    │ Worker            │
                    │ Policy Engine     │
                    │ Monitoring        │
                    └─────────┬─────────┘
                              │
                             mTLS
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │ Germany-01 │   │ Germany-02 │   │ NL-01      │
       │            │   │            │   │            │
       │ VPN Agent  │   │ VPN Agent  │   │ VPN Agent  │
       │ Xray       │   │ Xray       │   │ Xray       │
       │ WireGuard  │   │ WireGuard  │   │ WireGuard  │
       │ Hysteria2  │   │ Hysteria2  │   │ Hysteria2  │
       │ AdGuard    │   │ AdGuard    │   │ AdGuard    │
       └────────────┘   └────────────┘   └────────────┘
```

## 2. VPN Node Lifecycle

- Add secure one-time VPN-node enrollment.
- Generate short-lived node enrollment tokens.
- Exchange enrollment token for permanent node identity.
- Invalidate enrollment tokens after use.
- Issue unique mTLS identities per node.
- Support agent certificate renewal.
- Support agent certificate rotation without downtime.
- Support node revocation.
- Add node capacity metadata.
- Enforce node capacity rather than treating it as informational.
- Add capacity-aware assignment.
- Add node states `ACTIVE`, `DRAINING`, `MAINTENANCE`, `DISABLED`.
- Prevent new assignments to draining nodes.
- Keep existing sessions alive while draining when safe.
- Support device/profile migration to another node.
- Support graceful node removal.
- Support rolling upgrades.
- Add automatic post-upgrade health validation.
- Roll back upgrades/configuration if validation fails.
- Make a clean Ubuntu VPS reproducibly installable as a Nebula node.
- Minimize manual SSH steps during new-node setup.
- Add unattended/cloud-init installation later.
- Validate actual host state against expected state.

## 3. Desired-State Reconciliation

- Keep PostgreSQL/control plane as the desired-state authority.
- Extend existing WireGuard reconciliation to all connection engines: WireGuard peers, Xray credentials, Xray profiles, Hysteria2 users, DNS policies, node capabilities, firewall state, routing policies, and certificates where appropriate.
- Detect configuration drift.
- Automatically repair safe drift.
- Leave ambiguous drift for operator review.
- Never treat a lost agent response as definite failure.
- Make operations idempotent.
- Preserve operation IDs across retries.
- Surface desired vs actual state in admin UI.

```
Desired: REVOKED
Actual:  ACTIVE
State:   DRIFT
Action:  Retry pending
```

## 4. Supported Connection Engines

**Current / core:** WireGuard, VLESS, XHTTP, WebSocket, gRPC, raw TCP where
useful, TLS, REALITY, Hysteria2.

**Worth considering:** AmneziaWG, Shadowsocks, Trojan, TUIC, AnyTLS, SOCKS
profiles, HTTP proxy profiles.

**Specialized restricted-network engines:**

- Investigate DPI-bypass companion engine.
- Investigate alternative relay/fallback engines.
- Keep experimental transports behind capability flags.
- Do not expose experimental transports as stable before full leak/reliability tests.

Do not add protocols merely for protocol-count parity with 3x-ui/v2rayN.
Every protocol must justify its security review, client implementation,
server implementation, credential lifecycle, monitoring, reconciliation,
upgrade path, failure modes and maintenance burden.

## 5. Protocol Capability Registry

- Maintain a centralized reviewed capability registry.
- Define valid protocol + transport + security combinations.
- Reject free-form unsupported combinations.
- Version capabilities.
- Expose supported and deprecated capabilities to clients.
- Support minimum client versions per capability.
- Support server-specific capability availability.
- Add profile lifecycle states `ACTIVE`, `DEPRECATED`, `DISABLED`.
- Add migration target profile.
- Support profile migration periods.
- Preserve existing profile functionality during a deprecation window.
- Automatically provision replacement credentials before removal.
- Warn clients/admins about deprecated profiles.

## 6. Automatic Protocol Selection

- Add true Automatic mode that chooses the most appropriate protocol.
- Consider latency, handshake success, packet loss, recent failures, throughput, long-transfer reliability, network type, UDP availability, censorship conditions, and protocol history for the current network.
- Avoid relying only on ping.
- Store short-term protocol health.
- Do not store browsing destinations.

Potential fallback chain (the exact ordering should be dynamic rather than
permanently hardcoded):

```
Preferred / best measured
        ↓
XHTTP
        ↓
WebSocket
        ↓
REALITY
        ↓
Hysteria2
        ↓
WireGuard
```

## 7. Automatic Protocol Fallback

- Detect connection failure, handshake failure, successful startup with unusable traffic, transport reset, and repeated packet loss.
- Automatically retry an alternative profile.
- Limit fallback loops.
- Respect manually pinned protocols.
- Explain fallback to the user.
- Preserve diagnostics about the failed attempt.
- Avoid leaking credentials during retries.

## 8. Automatic Server Failover

- Automatically fail over between nodes.
- Respect manually pinned servers.
- Detect server health independently from protocol health.
- Prefer same-region replacement first; fall back to another region if needed.
- Avoid unhealthy/capacity-full nodes.
- Track recent failures.
- Add backoff before retrying a repeatedly failed node.

```
DE-01
  ↓ failure
DE-02
  ↓ failure
NL-01
```

## 9. Connection Quality Scoring

Build a quality score from latency, jitter, packet loss, handshake time,
connect success rate, recent disconnects, throughput, large-transfer
reliability, server load, current capacity, and historical stability on the
current network.

- Do not treat a TCP port opening as a successful VPN test.
- Continue testing traffic through the actual transport.
- Add optional throughput testing; keep heavy bandwidth tests user-triggered.
- Use small safe health probes automatically.

## 10. Continuous Tunnel Health

Borrow the strongest ideas from WhiteVPN Desktop while keeping Nebula's
stronger control-plane model.

- Verify that a tunnel actually carries traffic after connection.
- Periodically verify the tunnel remains usable.
- Detect "Protected/Connected" state with zero usable traffic.
- Tear down false-positive connections.
- Automatically reconnect, switch protocol, or switch server when appropriate.
- Respect manual server/profile pinning.
- Avoid constant high-frequency bandwidth tests; use a small neutral connectivity probe.
- Keep health checks privacy-preserving.

## 11. Clean-IP / CDN Discovery

Borrow the useful concept from WhiteDNS/WhiteVPN.

- Add clean-IP scanning, including Cloudflare/CDN IP scanning where useful.
- Test candidate IP reachability; measure latency, connection reliability and optionally lightweight throughput.
- Cache successful candidates temporarily; expire stale results.
- Allow manually pinned clean IPs and automatic candidate rotation.
- Keep hostname/SNI semantics correct when connecting by IP.
- Ensure TLS verification remains valid; do not disable certificate verification just to make clean-IP routing work.

## 12. DNS Architecture

- Deploy self-hosted AdGuard Home on VPN nodes; stop relying exclusively on public filtering DNS.
- Keep upstream resolvers configurable.
- Support encrypted upstream DNS: DoH, DoT, and standard DNS where needed.
- Add resolver health checking and fallback.
- Keep DNS inside the tunnel; prevent ISP resolver fallback.
- Add DNS leak detection.
- Keep DNS policy independent from VPN protocol where possible.

## 13. DNS Protection Profiles

Default, Privacy, Ads, Ads + trackers, Malware/phishing, Family protection,
Custom, Custom upstream, Custom blocklists, Custom allowlists.

Support per-user, per-device and per-profile DNS policies,
administrator-enforced policies, and user-overridable policies where allowed.

## 14. Multi-Layer Ad Blocking

Keep the current Xray approach and extend it rather than replacing it.

- Layer 1: AdGuard Home → DNS filtering.
- Layer 2: Xray sniffing → HTTP / TLS / QUIC hostname → domain rules → blackhole.
- Layer 3: optional client-side filtering.

- Keep Xray domain blackhole rules.
- Maintain explicit safe blocking lists or generated datasets.
- Avoid breaking required CDN domains.
- Keep DNS and Xray blocking policies synchronized where useful.
- Make protection capabilities visible by protocol.
- Improve Hysteria2 filtering parity.
- Clearly show when a transport only receives DNS-level protection.
- Do not claim YouTube video-ad blocking at network level when it cannot be reliably provided.

## 15. DNS Privacy

- Do not collect long-term DNS query history by default.
- Disable AdGuard query logs or drastically shorten retention.
- Never turn DNS infrastructure into browsing surveillance.
- Expose DNS logging policy in admin.
- Keep aggregate statistics separate from query logs; allow privacy-preserving counters such as number blocked.
- Do not associate domain history with named user accounts.

## 16. IPv6

Either support IPv6 properly or fail closed: IPv6 tunnel addressing, routing,
DNS, AAAA resolution, firewall, management-network blocking, kill switch, leak
detection, split routing, server capability detection and node health
testing. Verify all protocol engines under IPv6 before enabling it globally.
Until then, explicitly prevent unsafe IPv6 fallback.

## 17. Kill Switch

Build real platform-specific kill switches. Test: VPN server disappears;
Xray, WireGuard, Hysteria2, the VPN helper, or the app crashes; the app is
force-killed; Wi-Fi or mobile network disappears; Wi-Fi ↔ mobile; laptop
sleep and wake; Android sleep/doze; battery saver; Windows network adapter
restart; routing table change; DNS resolver failure; control plane
unavailable; VPN node temporarily unavailable.

## 18. Leak Protection

Add automatic diagnostics for public IPv4, public IPv6, DNS, routing, WebRTC
where meaningful, the VPN interface and local routes. Verify the expected exit
IP, expected resolver and VPN server country; compare advertised country with
measured exit country, and prefer measured truth over metadata.

## 19. Split Tunneling

Full VPN mode; per-app inclusion and exclusion; per-domain inclusion and
exclusion; per-IP inclusion and exclusion; CIDR rules; country/geosite-style
groups; sanctions/blocked-services-only mode; direct local-country traffic
mode; custom rules; an explicit LAN access option (exclude or include router,
printer, NAS); validate conflicting rules; display effective routing clearly.

## 20. Routing Presets

Normal users should see simple options: Automatic, Full VPN, Restricted
services only, Exclude local-country services, Selected apps only, Custom.
Advanced users can see actual routing rules.

## 21. Advanced Routing

Borrow the power of 3x-ui/v2rayN without forcing it on normal users: route by
domain, IP/CIDR, protocol, port, application where supported, or
country/category; route to direct, a selected VPN node, a selected protocol, a
proxy outbound, WARP, or blackhole; ordered rules; detect conflicting rules;
preview the effective route; test routing rules before activation.

```
Iranian sites     → Direct
Netflix           → NL-01
Telegram          → DE-02
Games             → Lowest-latency node
Everything else   → DE-01
Ads/trackers      → Blackhole
```

## 22. Load Balancing

Later-stage: balance across multiple VPN nodes (latency-, load-, health-aware,
weighted), fallback groups, balancer-to-balancer fallback, avoid flapping,
sticky policy where required. Do not implement before normal failover is
reliable.

## 23. Outbound Chaining

Advanced mode: VPN node → another VPN node / SOCKS / HTTP proxy / WARP /
custom upstream proxy; chained proxy health validation; prevent routing
loops; clearly show increased latency/security tradeoffs.

## 24. Client Modes

Primary modes: Automatic, Fast, Reliable, Restricted Network, Manual /
Advanced. Automatic should hide implementation details; Advanced should
expose them.

## 25. Server Picker

Show region, country, city, hostname/friendly name, measured exit country,
latency, packet loss, quality score, load, capacity, protocol health and
maintenance status. Support favorite, pinned and automatic server selection,
search/filter, and country and protocol filters.

## 26. Protocol Picker

Automatic mode, manual mode, latency result, throughput result, last success,
last failure, stability indicator, availability, filtering capability, UDP
capability, current network compatibility.

## 27. Server Workbench

Borrow this strongly from WhiteVPN/v2rayN: test all servers and all
protocols; latency, reachability, throughput, packet-loss and long-transfer
tests; sort by latency, throughput, reliability, quality or country; save
results temporarily; avoid test storms against the control plane.

## 28. Subscription and Import Compatibility

Nebula should not require every advanced user to use only Nebula-generated
profiles. Support optional import of VLESS URLs, Hysteria2 URLs, WireGuard
configs, Trojan URLs, Shadowsocks URLs, VMess URLs if VMess is supported,
SOCKS and HTTP proxy profiles, Clash/Mihomo YAML, Xray JSON, subscription
URLs and plain Base64 link lists. Maintain strict validation. Keep external
profiles clearly separated from centrally managed Nebula profiles.

## 29. Subscription Management

Custom subscriptions; automatic refresh with a configurable interval;
last-valid offline cache; source fallback; manual refresh; edit and delete;
subscription health; import preview; duplicate detection; fail safely on
malformed input.

## 30. Profile Sharing

For externally shareable profiles where policy permits: QR code, share link,
config export, selected-profile export, short-lived export links,
authentication where possible. Do not replace Nebula's per-device
authenticated credential model with permanent public subscription URLs.

## 31. Client Platforms

Priority: Android, Windows. Then macOS and Linux. Later, if justified: iOS.
Quality on two platforms is more important than mediocre support on five.

## 32. Client Runtime Modes

Full TUN VPN, local SOCKS proxy, local HTTP proxy, system proxy mode,
background/tray operation, start at boot, auto-connect, reconnect after sleep
and after network transition, restore previous connection safely.

## 33. Android Networking

Test and support Android 8+, VpnService, app inclusion/exclusion, doze,
battery saver, foreground service rules, network transitions, Wi-Fi/mobile
handoff, captive portals, process death, reboot, and Always-on / lockdown VPN
compatibility where practical.

## 34. Windows Networking

Robust TUN/Wintun handling; administrator elevation only when genuinely
needed; safe helper process design; safe process cleanup; clean temporary
credential files; startup cleanup; resume from sleep; interface transitions;
tray operation; system proxy mode; installer; portable build if useful;
Windows ARM64 later if justified.

## 35. Device Management

User-friendly device names, platform, app version, creation time, last
connection, current server, profile and session; revoke, disable and rename
devices; enforce and display the device limit; independently revoke protocol
credentials.

```
Parsa's OnePlus
Android
Last seen: 2 min ago
Server: DE-01
Protocol: XHTTP
Status: Connected
```

## 36. User Access Policies

Per user: allowed protocols, profiles and servers; device limit; account
expiry; traffic quota and reset interval; DNS policy; routing policy;
bandwidth limits later if needed.

## 37. Traffic Quotas

Borrow the useful management concepts from 3x-ui: total usage quota,
upload/download accounting, renewal/reset periods, expiry date, scheduled and
admin resets, user-visible remaining quota, warnings before exhaustion, safe
disabling of provisioning/access on exhaustion. Keep traffic accounting
aggregate; never record destination history.

## 38. Usage Statistics

Privacy-preserving per-user, per-device, per-server and per-protocol traffic;
active devices and tunnels; total tunnel uptime; connection attempts and
failures. Avoid destination sites, DNS history, URL history and packet
contents.

## 39. Online Status

Active/inactive device status, recent handshake, recent authenticated tunnel
activity, server-visible health; avoid claiming precise online state when
evidence is stale; expose the timestamp of the last evidence.

## 40. Admin Dashboard

Overview, Users, Devices, Sessions, Servers, Protocols, Profiles,
Permissions, Assignments, Routing, DNS, Usage, Health, Reconciliation,
Backups, Certificates, Security, Audit Log, Email Deliveries, Settings.

## 41. Admin Server Management

Add, enroll, disable, drain, put into maintenance, and safely delete servers;
show agent health and version, supported capabilities, active devices,
traffic, CPU, RAM, disk, bandwidth, protocol health and reconciliation state.

## 42. Admin Security Status

One factual security dashboard:

```
API                       Healthy
PostgreSQL                Healthy
Redis                     Healthy
Worker                    Healthy

Last backup               6h ago
Backup status             OK

TLS expires               63 days
Agent certificates        Valid
JWT key                   Current
MFA key                   Current

Security scan             Passing
Container scan            Passing
Secret scan               Passing

Reconciliation            Clean
Database schema           Current
```

## 43. Monitoring

Privacy-preserving metrics for API, database, Redis, worker, VPN agent, Xray,
WireGuard, Hysteria and DNS health; CPU, RAM, disk, network throughput,
packet loss; active tunnels; connection success, failure and
per-protocol failure rates; reconciliation errors; backup state; certificate
lifetime.

## 44. External Monitoring

Monitor the control plane and VPN nodes from outside the VPS; detect complete
host outage, DNS failure, TLS failure and regional reachability issues; keep
probes non-sensitive.

## 45. Alerts

Alert on: node or control plane unreachable; database, Redis, worker, VPN
Agent, Xray, WireGuard, Hysteria or DNS unhealthy; reconciliation failure;
disk > 80% and > 90%; capacity nearly exhausted; backup failed or stale; TLS
or agent certificate expiry approaching; unusual connection failure spike.
Possible integrations later: email, Telegram, Discord, generic webhooks.

## 46. Maintenance Mode

Global, node, and protocol/profile maintenance modes; block new
provisioning; preserve existing tunnels when safe; show maintenance state and
expected availability to clients.

## 47. Live Runtime Updates

Where safe: add and revoke Xray clients without restarting all of Xray or
dropping unrelated connections; update routing rules and allowed profile
state safely; minimize disruptive full-core restarts; validate live updates
before committing desired state; fall back to atomic restart when live
mutation is unsafe.

## 48. Firewall Security

Declarative firewall policy; automatically verify actual firewall state;
limit agent access to expected networks; restrict database/Redis to internal
networks; restrict admin/control-plane ports; restrict management interfaces
from VPN clients; regression-test firewall behavior; keep personal/internal
services unreachable from VPN users.

## 49. Internal Network Isolation

Permanent tests must ensure connected VPN users cannot reach localhost
services, control-plane private addresses, PostgreSQL, Redis, Docker
networks, the Xray management API, the VPN Agent management interface,
internal metrics endpoints, admin-only services, or host-only services unless
deliberately allowed. Repeat for IPv4 and IPv6.

## 50. Authentication

Preserve and strengthen: Argon2id passwords, Ed25519 access JWTs, rotating
opaque refresh tokens, refresh-family reuse detection, per-device sessions,
immediate revocation, neutral account recovery responses, password reset,
activation flow, session expiration, rate limiting, lockout, account
enumeration resistance.

## 51. Administrator Authentication

Keep a separate admin identity realm, password + TOTP, recovery codes,
step-up MFA, HttpOnly SameSite sessions, CSRF protection, origin checks,
session expiration, lockout, rate limiting, admin session visibility and
remote session revocation. Add WebAuthn/passkeys and hardware security key
support where possible.

## 52. Admin Roles

When multiple administrators become necessary: Owner, Security Admin,
Operator, Support, Read Only, with granular permissions rather than one giant
admin role.

## 53. Key Management

Manage JWT signing keys, token peppers, MFA encryption keys, Xray credential
encryption keys, the agent CA and certificates, TLS certificates and backup
encryption keys. Track current and previous accepted versions, creation time,
rotation status and expiry.

## 54. Safe Key Rotation

```
Generate new
    ↓
Publish verification/decryption material
    ↓
Switch active key
    ↓
Verify
    ↓
Keep old during migration
    ↓
Retire old
```

Automate safe stages, support rollback, detect incomplete rotations, and
prevent accidental loss of required previous keys.

## 55. Certificate Lifecycle

Monitor TLS and mTLS expiry; automate renewals safely; alert well before
expiry; support overlapping old/new certificates; verify a new certificate
before switching; support node certificate revocation.

## 56. Privacy Model

A dedicated privacy document explaining what the control plane stores, what
VPN nodes store, what DNS servers and administrators see, what clients send,
what telemetry exists, what is never collected, retention periods, IP
metadata, traffic usage and audit retention, and the deletion process.

## 57. Privacy Principles

Never collect browsing history, packet contents, destination URLs, complete
DNS history, private keys, plaintext credentials, plaintext reset/activation
tokens, client configs in logs, or Xray credentials in logs. Keep
operational metadata minimal.

## 58. Data Retention

Define requester-data, audit, auth-event, email-event, usage-data,
server-health and reconciliation retention; automatically prune expired data;
test pruning regularly.

## 59. Account Deletion

User- and admin-triggered deletion that revokes active sessions, WireGuard
peers, Xray and Hysteria credentials, deletes or anonymizes retained metadata
according to policy, and preserves legally/security-required audit records
only as defined.

## 60. Backup System

Complete the existing design: deploy the real Backblaze B2 backup; configure
the age public key and keep the private key offline; daily PostgreSQL
backups; back up required secrets; encrypt before upload; 30-day lifecycle
retention; monitor backup success; alert on stale backups; test backup
integrity.

## 61. Disaster Recovery

Document recovery from database corruption, Redis loss, control-plane VPS
loss, VPN node loss, secret-file loss, JWT key loss, MFA key loss, agent
certificate loss, broken deployment, failed migration, and compromised node.

## 62. Restore Testing

Quarterly: provision a clean host; restore PostgreSQL, secrets and deployment
identity; verify migration state, users, devices, assignments, encrypted
credentials, node reconnection, admin login and new VPN provisioning. A
backup is not considered proven until restored successfully.

## 63. Release Pipeline

Deterministic/repeatable builds where possible; tagged releases built through
CI; a release manifest with SHA-256 hashes; cryptographic signatures; signed
update metadata; source revision in artifacts; exact dependency versions;
binary component hashes.

## 64. Windows Release Security

Signed installer and executable; verify update signatures and the release
manifest; prevent arbitrary update URL execution; eventually obtain a trusted
code-signing identity.

## 65. Android Release Security

Stable signing key with secure custody and a reproducible signing process;
verify update metadata; prevent downgrade attacks where appropriate; publish
release checksums/signatures.

## 66. Update Channels

Internal, beta and stable, with channel-specific release metadata, safe
automatic update, user-controlled update behavior, rollback, staged rollout
later, and minimum supported version enforcement only when required.

## 67. Release Authenticity

Borrow the security principle used by v2rayN/3x-ui: publish SHA-256 and a
signature; the client and updater verify hash/signature and abort on
mismatch; protect against compromised mirrors/CDNs; do not trust transport
TLS alone for application updates.

## 68. SBOM and Supply Chain

Generate SBOMs for releases recording Python, npm and Dart packages, native
binaries, and the Xray, Hysteria, WireGuard and plugin versions. Add
provenance/attestation later.

## 69. Dependency Security

Keep Dependabot, Gitleaks, Trivy, container scanning, strict lock files and
pinned Actions. Add automated compatibility tests and a real connection test
for protocol-core upgrades; prevent blind auto-merge of protocol-core
updates; verify upstream archive hashes; track native binary hashes.

## 70. Patched Third-Party Code

Minimize patches and document why each exists; pin the exact upstream
revision; automatically verify each patch applies and fail the build if not;
test patched behavior directly; periodically check whether upstream fixed the
issue; remove patches when no longer needed.

## 71. Licensing

Before public distribution: audit every dependency license (Xray, Hysteria,
WireGuard libraries, Flutter/native plugins, imported code, GPL
dependencies); keep THIRD_PARTY_NOTICES; never copy code from
source-available projects that prohibit reuse; independently implement ideas
rather than copying restricted source; decide Nebula's own license before
public release.

## 72. Automated Testing

Maintain very strong unit tests, branch coverage, linting, formatting, static
typing, migration tests, PostgreSQL and Redis integration tests, concurrency
tests, container tests and native WireGuard tests.

## 73. Real End-to-End Testing

Android → actual VPS; Windows → actual VPS; real WireGuard, VLESS, XHTTP,
WebSocket, gRPC, REALITY and Hysteria tunnels; real DNS, split routing, ad
blocking, server failover and protocol fallback.

## 74. Hostile Network Test Lab

UDP completely blocked or heavily throttled; QUIC blocked; TCP reset; long
connections reset; random packet loss; severe jitter; high latency; DNS
poisoning; UDP/53 or TCP/53 blocked; IPv6 DNS broken; transparent DNS
interception; server IP blocked; SNI filtering; selected CDN IP blocked;
local censorship blockpage injection.

## 75. Network Transition Testing

Android: Wi-Fi → LTE, LTE → Wi-Fi, airplane mode, phone sleep, doze,
background restrictions, captive portal. Windows: Wi-Fi disconnect, Ethernet
connect, sleep, resume, adapter reset, network switch, VPN process crash.

## 76. Chaos Testing

Kill the API during provisioning or after agent success before DB finalize;
drop agent responses; restart PostgreSQL during an operation, Redis during
refresh rotation, the worker during email delivery; kill Xray during a config
update; lose network during reconciliation; fill disk temporarily; corrupt
temporary configuration; fail backup upload; fail certificate renewal.

## 77. Client Diagnostics

A dedicated diagnostics screen:

```
VPN              Connected
Server           Germany 01
Protocol         XHTTP
Exit IP          91.x.x.x
Exit Country     Germany
DNS              Protected
DNS Resolver     Nebula AdGuard
DNS Leak         None
IPv6 Leak        None
Packet Loss      0.3%
Handshake        184 ms
Download         26 Mbps
Upload           9 Mbps
Ad Blocking      Enabled
Kill Switch      Enabled
```

## 78. Diagnostic Export

Sanitized export of app version, OS version, tunnel type, anonymized server
identifier if needed, protocol state, failure class and recent local logs.
Never export private keys, raw auth or refresh tokens, passwords, Xray
UUIDs/passwords, full client configs, visited domains or DNS history.

## 79. Failure Messages

Differentiate: internet unavailable; DNS unavailable; server unreachable;
protocol blocked; TLS verification failure; authentication rejected;
handshake timeout; tunnel started but no traffic; server stopped responding;
local VPN adapter failure; permission/elevation failure; configuration
invalid; control plane unavailable. Avoid generic "Connection failed"
whenever a useful classification exists.

## 80. Client Localization

Keep and expand English, Persian (correct RTL), German, French, Spanish,
Arabic, Russian, Turkish, Chinese, and others based on actual demand; keep
technical terms consistent; do not expose untranslated protocol internals in
normal mode.

## 81. Client Design

System, light and dark themes; reduced-motion support; accessible labels;
keyboard navigation on desktop; responsive layouts; clear offline,
maintenance, expired-account and restricted-access states.

## 82. Simple User Experience

The main screen should eventually be close to:

```
        NEBULA

      Protected

      Germany
      Automatic

   [ Disconnect ]
```

Normal users should not need to understand VLESS, gRPC, XHTTP, REALITY,
Hysteria, MTU, mux or fragmentation. Those belong under Advanced.

## 83. Advanced User Experience

Advanced users may configure server, protocol, transport, DNS, routing mode,
split tunnel, fragmentation, mux, IPv6 preference, proxy mode, local ports,
logging level and imported profiles.

## 84. Logging

Fault-only by default; optional diagnostic level; a clear warning when
destination logging is enabled; automatic expiration of verbose logs; redact
secrets, credentials and tokens; avoid full config dumps.

## 85. Crash Reporting

If introduced: opt-out/consent where appropriate; scrub tokens, credentials,
VPN config, domain history and unnecessary private IP data; never upload raw
tunnel logs automatically.

## 86. API Versioning and Capability Negotiation

Version API contracts; expose client/server compatibility and the capability
list; allow old clients to operate safely; reject unsupported behavior
clearly; test old client → new server and new client → older supported
server; prevent silent semantic changes.

## 87. Backward Compatibility

Maintain tests for at least recent releases: previous and current stable
Android and Windows clients against the current API and server capabilities.

## 88. Profile Migration

Migration target, deprecation date, warning period, new credential
provisioning, client migration prompt, automatic migration when safe, old
credential revocation after the deadline, operator override.

## 89. Audit System

Append-oriented audit logs for authentication, admin login, MFA, user
approval and rejection, device creation and revocation, permission and
assignment changes, node enrollment and removal, profile changes,
reconciliation, key rotation, backup operations and administrative security
actions.

## 90. Tamper-Resistant Audit Export

Later: periodic signed audit snapshots to external storage, hash chains or
signed batches, export integrity verification, and preventing ordinary admin
action from silently rewriting history.

## 91. Documentation

Make documentation match reality: README, architecture, threat model,
current capabilities, supported platforms and protocols, deployment guide,
VPN-node guide, disaster recovery, backup restore, key rotation, release
process, privacy model, troubleshooting, contributor guide.

## 92. Documentation Drift

Choose one canonical current-status file; avoid duplicating status across
files; generate the app version, supported protocol list and capability
tables where possible; validate documentation references in CI; update the
roadmap with completed items in the same PR.

## 93. Architecture Diagrams

Control plane, VPN node, authentication, provisioning, WireGuard lifecycle,
Xray lifecycle, DNS path, ad blocking, routing, multi-node failover, key
management, backups, trust boundaries.

## 94. Installation Experience

For self-hosters: a prerequisites checker; guided and unattended install;
generated random initial secrets with secure placement; validation of ports,
DNS, firewall, TLS and system resources; a post-install health check and a
clear result. Eventually `curl ... | nebula-install`, only if it can be done
securely and transparently; prefer signed downloaded installers over blind
remote shell execution.

## 95. Self-Hosting Modes

Single-host personal install; separated control plane + VPN node; multi-node
install; external PostgreSQL; external Redis if justified; managed DNS;
self-hosted AdGuard. Keep single-host mode available for small personal
setups even after the distributed architecture exists.

## 96. Resource Limits

CPU and memory limits; disk monitoring; log rotation; PostgreSQL and Redis
storage monitoring; node bandwidth monitoring; application queue limits;
request body limits; timeouts; connection limits.

## 97. Database

Continue PostgreSQL as the primary database with explicit Alembic
migrations, an application role without DDL, a migrator role, schema-head
readiness checks, concurrency tests, restrictive foreign keys and append-only
audit protections. Add migration recovery drills, production migration
verification, index/performance monitoring, and capacity forecasting later.

## 98. Redis

Private/internal only; authentication; persistence; session TTL; safe
failure behavior; test restart and unavailability; define which operations
fail closed; avoid making established VPN traffic depend on Redis.

## 99. Email

Continue the durable outbox, retry/backoff, neutral account emails, Resend
support, SMTP abstraction and delivery observability. Add provider health,
alerts on repeated delivery failure, and safe provider fallback later if
necessary.

## 100. User Self-Service

See account status, devices, sessions, usage, expiration and quota; rename
and revoke own devices; revoke sessions; change and reset password; manage
optional DNS preferences; export sanitized diagnostics.

## 101. Public Release Readiness

Before public distribution: dedicated infrastructure; second node tested;
backup deployed and restore tested; signing implemented; privacy policy and
data retention complete; license chosen; third-party license audit complete;
update mechanism secured; kill switch, DNS leaks and IPv6 posture tested;
real-device E2E passing; disaster-recovery runbook tested; external security
review if practical.

## 102. What to Borrow from WhiteVPN

One-tap simple UX; built-in Automatic behavior; manual server selection;
latency and download-speed tests; automatic connection recovery; subscription
support with offline cache; per-app split tunnel; global/full VPN mode;
local-country bypass mode; clean-IP scanning; LAN sharing concepts if
appropriate; DoH/DoT; real exit-country verification; server workbench. Do
not copy code unless licensing explicitly permits and the architecture
benefits from it.

## 103. What to Borrow from WhiteDNS

Think beyond standard VPN protocols; specialized censorship-resistance engines;
resolver profiles; connection progress visibility; traffic statistics; split
routing; engine abstraction; clean-IP ecosystem ideas. WhiteDNS
source-available components that prohibit reuse must only inspire
independently implemented behavior.

## 104. What to Borrow from 3x-ui

Rich server administration; per-user quotas, expiry and device/IP limits;
usage resets; live user status; traffic accounting; multi-node management;
node cloning concepts where appropriate; routing rules; outbound chaining;
load balancers; fallback groups; WARP upstream; live Xray updates; unattended
installation; API documentation; remote monitoring integrations. Do not copy
3x-ui's complexity into the normal client UX.

## 105. What to Borrow from v2rayN

Desktop power-user flexibility; broad profile import and subscription
compatibility; advanced TUN settings; configurable routing; multi-core
abstraction concepts; Windows/Linux/macOS packaging maturity; system proxy
behavior; signed release verification; power-user diagnostics. Keep these
behind Advanced mode.

## 106. What Nebula Should Keep as Its Advantage

Do not lose these while chasing feature parity: centralized account and
device systems; per-device credentials; independent revocation; per-user
protocol permissions and server assignments; a proper control-plane
database; the typed VPN Agent API; mTLS; no arbitrary root shell from the
public API; desired-state reconciliation; strong token lifecycle; admin MFA;
CSRF protection; audit events; privacy-focused logging; real production
testing; real failure-driven regression testing. These are what make Nebula
more than another VPN panel.

## 107. Features to Avoid Rushing

Payments; subscriptions/billing; affiliate systems; dozens of protocols; iOS
before Android/Windows quality is strong; macOS before Windows client
reliability is strong; huge analytics platforms; invasive telemetry; AI
features without a real use case. Reliability first.

## 108. Recommended Development Order

**Phase A — Production Foundations.** 1. Dedicated Nebula production
VPS/infrastructure. 2. Separate control plane and VPN node. 3. Deploy
backups for real. 4. Perform restore drill. 5. Add external monitoring.
6. Add alerts. 7. Update documentation to current reality.

**Phase B — Multi-Node.** 8. Add second VPN node. 9. Secure node enrollment.
10. Node certificate lifecycle. 11. Node health monitoring. 12. Capacity-aware
assignments. 13. Node draining. 14. Maintenance mode. 15. Node migration.
16. Automatic server failover.

**Phase C — Smart Client.** 17. Automatic protocol selection. 18. Automatic
protocol fallback. 19. Continuous tunnel health. 20. Connection-quality
scoring. 21. Throughput testing. 22. Packet-loss testing. 23. Clean-IP
scanning. 24. Diagnostics screen. 25. Better failure explanations.

**Phase D — DNS and Privacy.** 26. Self-hosted AdGuard Home. 27. DNS policy
system. 28. Per-user DNS. 29. Per-device DNS. 30. Preserve Xray hostname
blackhole. 31. Improve Hysteria filtering parity. 32. DNS leak detection.
33. DNS privacy/retention controls.

**Phase E — Routing.** 34. Split tunneling. 35. Per-app rules. 36. Per-domain
rules. 37. LAN access control. 38. Routing presets. 39. Advanced routing.
40. Outbound chaining later. 41. Load balancing later.

**Phase F — Administration.** 42. Traffic statistics. 43. User quotas.
44. Expiry. 45. Device limits. 46. Online status. 47. Admin server controls.
48. Security dashboard. 49. Reconciliation dashboard. 50. Backup/certificate
dashboards.

**Phase G — Client Ecosystem.** 51. Mature Android. 52. Mature Windows.
53. Subscription/import compatibility. 54. Profile workbench. 55. macOS.
56. Linux. 57. iOS only when justified.

**Phase H — Distribution Security.** 58. Windows code signing. 59. Android
release signing workflow. 60. SHA-256 release manifests. 61. Cryptographic
release signatures. 62. Signed updater metadata. 63. Update channels.
64. SBOM. 65. Provenance/attestation.

**Phase I — Advanced Resilience.** 66. IPv6. 67. Full kill-switch matrix.
68. Hostile-network CI/lab tests. 69. Chaos testing. 70. Live runtime
configuration. 71. Rolling upgrades. 72. Multi-region balancing.
73. Alternative restricted-network transports.

## 109. Definition of the Final Product

The intended result is not "3x-ui clone + v2rayN clone + WhiteVPN clone +
AdGuard". The target is:

```
                         NEBULA
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
       CLIENTS         CONTROL PLANE       VPN FLEET
          │                 │                 │
 Android/Windows       Accounts          WireGuard
 macOS/Linux           Devices           Xray
                       Permissions       Hysteria2
 Automatic Mode        Assignments       DNS
 Advanced Mode         Policies          Future Engines
 Diagnostics           Routing
                       Monitoring
                       Reconciliation
                       Backups
                       Security
```

The normal user experience should eventually be:

```
Install Nebula
      ↓
Sign in
      ↓
Press Connect
      ↓
Nebula automatically chooses:
    server
    protocol
    routing
    DNS
    failover
      ↓
Protected
```

The advanced user should still be able to control nearly everything. The
administrator should be able to operate the entire VPN fleet from one
system.
