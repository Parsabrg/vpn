# WireGuard and Xray protocol roadmap

## Product definition

The final Nebula VPN product offers user-selectable protocol profiles backed by two
runtime families:

1. **Native WireGuard** for a fast, minimal tunnel with device-generated keys.
2. **Xray-core** for reviewed proxy/tunnel profiles that combine a user-facing
   protocol, transport, and transport-security mode.

Delivery remains phased. Taking every Xray capability into account does not mean
enabling every possible combination or presenting internal routing primitives as
VPN choices.

## Capability classification

### User-selectable server protocols

| Protocol    | Role in Nebula                                     | Planned treatment                             |
| ----------- | -------------------------------------------------- | --------------------------------------------- |
| WireGuard   | Native full-tunnel option                          | Phase 1 baseline; not duplicated through Xray |
| VLESS       | Primary modern Xray protocol                       | First Xray milestone                          |
| Trojan      | TLS-oriented compatibility profile                 | Later reviewed Xray profile                   |
| Shadowsocks | Compatibility profile                              | Later; only reviewed modern cipher/settings   |
| VMess       | Legacy ecosystem compatibility                     | Later and disabled by default unless required |
| Hysteria2   | UDP/QUIC-oriented profile through Xray Hysteria v2 | Later network-specific milestone              |

### Xray transports and security modes

The capability registry accounts for:

- transports: RAW, XHTTP, mKCP, gRPC, WebSocket, HTTPUpgrade, and Hysteria
- security: TLS and REALITY
- optional protocol-specific flow such as XTLS Vision where valid

These are not a Cartesian product. Each enabled profile is an explicitly reviewed,
versioned tuple with compatible client platforms and server requirements. Xray's
current documentation recommends XHTTP over WebSocket and gRPC for new deployments;
WebSocket/gRPC therefore remain compatibility profiles rather than default choices.

### Internal-only Xray components

The following are taken into account but are not shown as remote VPN protocols:

- TUN: feeds OS-routed traffic into Xray on supported clients
- SOCKS and HTTP: local application ingress or upstream compatibility
- dokodemo-door: internal transparent-proxy building block
- Freedom, Blackhole, DNS, and Loopback: outbound routing primitives
- routing, FakeDNS, statistics, observatory, mux/XUDP, and sniffing: internal
  features governed by privacy and compatibility policy
- Xray's WireGuard inbound/outbound: advanced interoperability only; Nebula's public
  WireGuard option uses the separately managed native driver

## Delivery phases

### Phase 1 — secure control plane and native WireGuard

- Generic protocol/profile, permission, server-capability, device-credential, and
  provisioning-operation models
- Generic typed agent contract with native WireGuard driver
- Capability-driven protocol picker that shows only implemented profiles
- Complete approval, activation, device, revocation, audit, backup, and WireGuard
  lifecycle on Android and Windows

Exit gate: the WireGuard acceptance workflow passes and all Xray capabilities remain
disabled and impossible to provision.

### Phase 2 — Xray foundation and VLESS baseline

- Pinned Xray-core runtime and hardened Xray driver
- Trusted profile templates, native config validation, atomic apply, health,
  rollback, reconciliation, and per-device credential revocation
- Android TUN/VpnService and Windows TUN/Wintun client boundaries
- VLESS over XHTTP with TLS as the recommended reverse-proxy-friendly baseline
- VLESS over RAW with TLS or REALITY/XTLS Vision as a separately tested direct mode
- Secure authenticated profile delivery; no public subscription URLs

Exit gate: both WireGuard and at least one Xray VLESS profile pass connect,
disconnect, DNS/leak, network-change, expiration, device-limit, and revocation tests
on Android and Windows.

### Phase 3 — Xray compatibility expansion

- VLESS transport profiles for gRPC, WebSocket, HTTPUpgrade, and mKCP where a real
  deployment requirement justifies them
- Trojan, Shadowsocks, and VMess profiles with explicit security and deprecation
  policy
- Profile migration, version negotiation, capability rollout, and compatibility
  test matrix

Exit gate: every enabled tuple has automated server validation plus recorded client
tests. Unsupported combinations remain rejected by the registry.

### Phase 4 — Hysteria2 and advanced routing

- Xray Hysteria v2 profile, UDP/QUIC firewall and NAT behavior, congestion and
  handover testing
- Optional split tunneling, per-app routing, FakeDNS, and policy routing after a
  privacy review
- Multi-server placement and profile-aware health/routing

Exit gate: no advanced routing feature is marketed until platform-specific DNS,
IPv4/IPv6 leak, kill-switch, and recovery behavior is verified.

## Protocol selection behavior

The API returns a list of profile capabilities intersected across:

- profiles implemented by the installed client version
- profiles enabled and healthy on the selected server
- profiles allowed for the user's account
- profiles permitted on the registered device/platform
- profiles that satisfy account expiry and revocation state

The UI shows a friendly profile name plus an advanced technical summary. Selecting
a profile provisions or retrieves only that device's credential. Switching profiles
does not silently reuse credentials between WireGuard and Xray.

## Credential rules

- WireGuard private keys are generated and stored only on the device.
- Xray credentials are unique per device/profile and treated as bearer secrets.
- The control plane stores Xray secrets only when required for reconciliation and
  then uses envelope encryption with a key outside the database.
- Raw credentials, profiles, QR payloads, and subscription links never enter logs,
  analytics, crash reports, email, audit metadata, or public URLs.
- Disabling a user revokes application sessions, native WireGuard peers, and every
  active Xray credential, with reconciliation until runtime state matches.

## Definition of complete Xray support

An Xray profile is complete only when its exact protocol/transport/security tuple:

- validates against the pinned Xray-core version
- provisions, connects, disconnects, expires, and revokes correctly
- survives restart and recovers from a failed apply
- passes Android and Windows TUN, DNS, IPv4/IPv6 leak, network-change, and kill-switch
  tests where the platform supports them
- has documented ports, TLS/REALITY ownership, resource limits, upgrade path, and
  client compatibility

Listing a capability in this roadmap does not claim that it is implemented.

## Official Xray references

- [VLESS inbound and protocol index](https://xtls.github.io/en/config/inbounds/vless.html)
- [VLESS outbound](https://xtls.github.io/en/config/outbounds/vless.html)
- [Xray TUN inbound](https://xtls.github.io/en/config/inbounds/tun.html)
- [XHTTP transport](https://xtls.github.io/en/config/transports/splithttp.html)
- [WebSocket transport](https://xtls.github.io/en/config/transports/websocket.html)
- [gRPC transport](https://xtls.github.io/en/config/transports/grpc.html)
- [Hysteria v2 transport](https://xtls.github.io/en/config/transports/hysteria.html)
