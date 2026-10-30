import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../routing/sanctioned_domains.dart';
import '../servers/server_repository.dart';
import '../storage/advanced_settings_store.dart';
import 'ech_source.dart';
import 'local_proxy.dart';
import 'windows_tunnel_config.dart';

/// A config that measures a profile's real delay, v2ray-style: the same
/// outbound a connection would dial -- mux and fragmentation included -- and
/// nothing else.
///
/// No inbound, because the plugin's delay test drives the outbound itself.
/// No routing or DNS, because a sanctions-only or ad-blocking rule would send
/// the test request somewhere other than the server and report on the wrong
/// path. Testing the dial a connection would really make is the point: a
/// profile that answers a TCP connect but carries nothing -- gRPC through
/// nginx did exactly that -- fails here, where a port check says it works.
String renderXrayDelayProbeConfigJson(
  XrayClientResult result, {
  AdvancedSettings settings = AdvancedSettings.defaults,
}) {
  return jsonEncode(<String, dynamic>{
    'log': logModuleFor(settings),
    'outbounds': <Map<String, dynamic>>[
      _withFragment(_withMux(_vlessOutbound(result), settings), settings),
      if (settings.fragment.enabled) fragmentOutbound(settings.fragment),
    ],
  });
}

/// Hysteria2's probe: the plugin starts the reference client from
/// `nebulaHysteriaConfig` for the length of the test, and Xray measures
/// through the client's local SOCKS port. Xray alone would test a connection
/// without Salamander, which is not the one a connect makes.
String renderHysteriaDelayProbeConfigJson(
  XrayClientResult result, {
  required LocalProxy localProxy,
}) {
  return jsonEncode(<String, dynamic>{
    'nebulaHysteriaConfig': _hysteriaYaml(result, localProxy),
    'nebulaHysteriaPort': localProxy.port,
    'outbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'protocol': 'socks',
        'settings': <String, dynamic>{
          'servers': <Map<String, dynamic>>[
            <String, dynamic>{
              'address': '127.0.0.1',
              'port': localProxy.port,
              'users': <Map<String, dynamic>>[
                <String, dynamic>{
                  'user': localProxy.username,
                  'pass': localProxy.password,
                },
              ],
            },
          ],
        },
      },
    ],
  });
}

/// WireGuard's probe, through Xray's own WireGuard client: the same key and
/// peer a connect would use, without raising the system tunnel.
String renderWireGuardDelayProbeConfigJson({
  required String privateKeyBase64,
  required WireGuardPeerResult peer,
}) {
  return jsonEncode(<String, dynamic>{
    'outbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'protocol': 'wireguard',
        'settings': <String, dynamic>{
          'secretKey': privateKeyBase64,
          'address': <String>['${peer.assignedAddress}/32'],
          'peers': <Map<String, dynamic>>[
            <String, dynamic>{
              'publicKey': peer.serverPublicKey,
              'endpoint': peer.publicEndpoint,
            },
          ],
        },
      },
    ],
  });
}

/// Renders the full Xray-core client JSON config for a VLESS/Hysteria2 peer
/// -- `flutter_v2ray_client` passes this straight through to the native
/// Xray core with no config synthesis of its own (confirmed against its
/// `V2RayURL.fullConfiguration`, which always includes `inbounds`), so
/// unlike [renderWireGuardConfig] this has to include a local inbound too,
/// not just the outbound that actually reaches [result]'s server.
///
/// Covers every transport the manual picker can offer: XHTTP, gRPC,
/// WebSocket, and raw TCP are all VLESS outbounds differing only in
/// `streamSettings`; Hysteria2 is a wholly different outbound `protocol`
/// (Xray-core's own native `"hysteria"` support, confirmed present in the
/// v26.3.27 build this deployment runs), identified by the bearer `auth`
/// string rather than a VLESS `id`.
///
/// [XrayClientResult.adBlock] blocks in two independent layers, because
/// either one alone leaks.
///
/// The `dns` module points at AdGuard's filtering resolver, which is the
/// mechanism the working ad-blocking config this was modeled on used, and
/// which `flutter_v2ray_client` also installs as the tunnel's own DNS server
/// (its V2rayVPNService reads `dns.servers` straight into
/// `VpnService.Builder.addDnsServer`). That covers anything which resolves
/// through the system -- and nothing which does not. A client doing
/// DNS-over-HTTPS never asks the tunnel's resolver at all; Chrome does this
/// by default, and plenty of apps ship hardcoded resolvers, so a DNS-only
/// build silently blocks far less than it appears to.
///
/// So the second layer routes on the domain Xray itself observes: `sniffing`
/// reads the real hostname out of the TLS handshake or HTTP request, and
/// anything matching [_adBlockDomains] is routed to a blackhole outbound.
/// That path cannot be bypassed by choosing a different resolver, because no
/// resolver is involved in it.
///
/// Deliberately an explicit domain list rather than Xray's `geosite:` rules:
/// those need geosite.dat alongside the binary, `flutter_v2ray_client` ships
/// no such asset, and a rule referencing a missing geo file fails config
/// load outright -- which would take the whole tunnel down rather than
/// degrade blocking.
///
/// [localProxy] locks the local SOCKS5 inbound that tun2socks dials; see
/// [LocalProxy] for why it has credentials and a port of its own.
///
/// [apiHosts] are the app's own API addresses. They always go through the
/// server, whatever the routing mode: sent straight out, on a network that
/// stalls them (mobile data, 2026-10-20) the tunnel worked while the account
/// and device list said "offline".
String renderXrayClientConfigJson(
  XrayClientResult result, {
  required LocalProxy localProxy,
  AdvancedSettings settings = AdvancedSettings.defaults,
  List<String> apiHosts = const <String>[],
  CdnDial cdnDial = CdnDial.asGiven,
}) {
  if (result.transport == 'hysteria') {
    return _renderHysteriaClientConfigJson(
      result,
      localProxy: localProxy,
      settings: settings,
    );
  }
  final Map<String, dynamic> config = <String, dynamic>{
    // Xray-core writes to Android's log under the `GoLog` tag, but only for
    // levels this block enables -- with no block at all it stays silent, and
    // a tunnel that fails to start looks identical to one that started fine.
    // That cost a long investigation: Hysteria2 reported connected, brought
    // `tun0` up, and sent nothing, and the core never said why because it had
    // never been asked to. `warning` is Xray's own default level; naming it
    // explicitly is what actually turns the output on.
    'log': logModuleFor(settings),
    // Both blocks together are what make the connect screen's byte counters
    // possible, and either alone is silently useless.
    //
    // Xray keeps no counters unless asked: with no `stats` block the core
    // records nothing, and with no `policy` naming the outbound counters the
    // stats object stays empty. The plugin then reads them by outbound tag
    // (`queryStats("proxy", "downlink")` in V2rayCoreManager), which is why
    // the outbound below is tagged `proxy` rather than left to Xray's
    // generated name. Miss any one of the three and every reading is zero --
    // which looks exactly like a tunnel nobody has used.
    'stats': <String, dynamic>{},
    'policy': <String, dynamic>{
      'system': <String, dynamic>{
        'statsOutboundUplink': true,
        'statsOutboundDownlink': true,
      },
    },
    // Always present, filtering or not. `flutter_v2ray_client` turns this into
    // the tunnel's own DNS servers (VpnService.Builder.addDnsServer), and when
    // it is absent it sets none at all -- which does not mean "no DNS", it
    // means Android falls back to the underlying network's resolver. Confirmed
    // against the real deployment: with no dns block the tunnel reported
    // `DnsAddresses: []` and a domain the local ISP forges resolved to its
    // injected address (10.10.34.x) rather than the real one, while traffic
    // itself was still going through the tunnel.
    //
    // That is not only a privacy leak -- the resolver seeing every domain
    // despite the VPN -- it defeats the tunnel outright for censored names,
    // because a forged answer sends the client to a blockpage address before
    // any tunnelled connection is attempted.
    'dns': dnsModuleFor(result, settings),
    'inbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'tag': 'socks-in',
        'listen': '127.0.0.1',
        'port': localProxy.port,
        'protocol': 'socks',
        'settings': _localSocksSettings(localProxy),
        // tun2socks hands Xray packets addressed by IP, so without this
        // there is no hostname for a routing rule to match on. Left at the
        // shipped behaviour by default -- on where a profile has rules to
        // feed, off where it has none, so nothing pays for a parse it
        // cannot use.
        if (sniffingEnabledFor(result, settings))
          'sniffing': <String, dynamic>{
            'enabled': true,
            // `quic` as well as the two TCP protocols. This inbound carries
            // UDP, and Chrome and YouTube reach much of the web over QUIC,
            // so reading only HTTP and TLS left the ad-block rules blind to
            // exactly the traffic that carries the most ads -- they matched
            // nothing and the request went straight through. The QUIC
            // sniffer is compiled into the core this app ships.
            'destOverride': <String>['http', 'tls', 'quic'],
          },
      },
    ],
    'outbounds': <Map<String, dynamic>>[
      // First outbound is Xray's default route, so the real one stays first
      // and the blackhole is only ever reached by an explicit rule below.
      _withFragment(
        _withMux(
          result.transport == 'hysteria'
              ? _hysteriaOutbound(result)
              : _vlessOutbound(result),
          settings,
        ),
        settings,
      ),
      if (settings.fragment.enabled) fragmentOutbound(settings.fragment),
      if (result.adBlock)
        <String, dynamic>{'tag': 'ad-block', 'protocol': 'blackhole'},
      if (routesAnythingDirect(result, settings))
        <String, dynamic>{'tag': 'direct', 'protocol': 'freedom'},
    ],
    if (result.adBlock || routesAnythingDirect(result, settings))
      'routing': <String, dynamic>{
        // An Iranian address can only be matched once there is one: with
        // sniffing the destination is a name, so a name no rule matches is
        // looked up (through the tunnel's resolver) and its address checked.
        // One cached lookup per new name, paid only with the toggle on.
        if (routesIranDirect(result, settings))
          'domainStrategy': 'IPIfNonMatch',
        'rules': <Map<String, dynamic>>[
          // First, so no direct rule below can claim the app's own API.
          if (routesAnythingDirect(result, settings) && apiHosts.isNotEmpty)
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'proxy',
              'domain': <String>[for (final String h in apiHosts) 'full:$h'],
            },
          if (result.adBlock)
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'ad-block',
              'domain': _adBlockDomains,
            },
          // After the ad block, so an ad served from a bypassed site is
          // still dropped; before everything else, so they win.
          if (result.transport != 'hysteria' &&
              settings.bypassDomains.any((String d) => !isBypassAddress(d)))
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'direct',
              'domain': <String>[
                for (final String d in settings.bypassDomains)
                  if (!isBypassAddress(d)) 'domain:$d',
              ],
            },
          // Addresses and ranges: matched on the destination address, so
          // they need no hostname read out of the connection.
          if (result.transport != 'hysteria' &&
              settings.bypassDomains.any(isBypassAddress))
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'direct',
              'ip': <String>[
                for (final String d in settings.bypassDomains)
                  if (isBypassAddress(d)) d,
              ],
            },
          if (routesIranDirect(result, settings)) ...<Map<String, dynamic>>[
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'direct',
              'domain': <String>['domain:ir', 'geosite:category-ir'],
            },
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'direct',
              'ip': <String>['geoip:ir'],
            },
          ],
          // Blocked ads first, so an ad served from a listed domain is still
          // dropped. Then the services that need a foreign address, then
          // DNS -- through the server as well, so name lookups keep working
          // and stay private however the local network treats port 53 --
          // and last everything else, straight out. Without that final rule
          // Xray would send unmatched traffic to its first outbound, which
          // is the server: the opposite of the mode.
          if (routesSanctionsOnly(result, settings)) ...<Map<String, dynamic>>[
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'proxy',
              'domain': sanctionedDomains,
            },
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'proxy',
              'port': '53',
            },
            <String, dynamic>{
              'type': 'field',
              'outboundTag': 'direct',
              'network': 'tcp,udp',
            },
          ],
        ],
      },
  };
  // A clean Cloudflare address chosen for this very route: the tunnel dials
  // it, while TLS and the Host header keep the route's name. Only the CDN
  // transports go through Cloudflare.
  final String? cleanIp = settings.cleanIpHost == result.serverAddress
      ? settings.cleanIp
      : null;
  if (cdnDial != CdnDial.asGiven && isCloudflareRoute(result)) {
    return jsonEncode(
      windowsXrayPinnedUpstream(
        withCdnDial(config, result.transport, cdnDial),
        result.serverAddress,
        cdnDial == CdnDial.ipv6 ? kCloudflareIpv6 : cleanIp ?? kFfCleanIp,
      ),
    );
  }
  if (cleanIp != null && cdnTransports.contains(result.transport)) {
    return jsonEncode(
      windowsXrayPinnedUpstream(config, result.serverAddress, cleanIp),
    );
  }
  return jsonEncode(config);
}

/// How a tunnel through Cloudflare is dialled. The firewalls in front of
/// Iran's two mobile operators each let a different shape through, and which
/// one a network uses changes (a Hamrah-e-Avval SIM can sit behind the
/// Irancell firewall), so the app tries them in turn and remembers the one
/// that carried traffic.
enum CdnDial {
  /// As the server hands it out: Encrypted Client Hello. Iran stopped
  /// answering `cloudflare-ech.com`, ECH's public name, on 2026-10-21.
  asGiven,

  /// No ECH, a plain Chrome hello and the transport's ALPN, through a clean
  /// address: partly through on a TCI home line on 2026-10-22 (1 request in 4
  /// and a whole 3 MB download) when nothing else Cloudflare carried was.
  plain,

  /// The "F&F" shape reported to pass the Irancell firewall: a clean
  /// Cloudflare address, the TLS hello split with a zero-length first piece
  /// (PattNG's "tlshello-0-len" finalMask), the `unsafe` fingerprint with
  /// Python's cipher order ("semi-python"), and the transport's own ALPN.
  ff,

  /// The shape reported to pass Hamrah-e-Avval's firewall, which blocks by
  /// list rather than by allow-list on IPv6: Cloudflare's IPv6 edge with a
  /// plain Chrome hello. Only for a device that has IPv6 at all.
  ipv6,
}

/// The dials to try, the one that worked last time first.
List<CdnDial> cdnDialOrder({CdnDial? lastWorked, required bool hasIpv6}) {
  final List<CdnDial> order = <CdnDial>[
    ?lastWorked,
    for (final CdnDial dial in CdnDial.values)
      if (dial != lastWorked) dial,
  ];
  return <CdnDial>[
    for (final CdnDial dial in order)
      if (dial != CdnDial.ipv6 || hasIpv6) dial,
  ];
}

/// A tunnel the server routed through Cloudflare: it hands those out with an
/// ECH key, and a free relay is a `workers.dev` name. The web-host front
/// (Vercel) is neither, and keeps its own dial.
bool isCloudflareRoute(XrayClientResult result) =>
    cdnTransports.contains(result.transport) &&
    (result.echConfigList != null ||
        result.sni.toLowerCase().endsWith('.workers.dev'));

/// A clean Cloudflare edge address, used when none was chosen in Settings.
const String kFfCleanIp = '188.114.98.0';

/// One of Cloudflare's IPv6 edge addresses.
const String kCloudflareIpv6 = '2a06:98c1:3101::6812:202f';

/// Python's first TLS 1.2 suites in Python's order, as Go names them (PattNG's
/// "semi-python" preset; see [CdnDial.ff]).
const String kSemiPythonCipherSuites =
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:'
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:'
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:'
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:'
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:'
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:'
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:'
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:'
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:'
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';

/// The proxy outbound redone for [dial]: no ECH, the dial's hello, and the
/// ALPN Cloudflare expects for this transport (HTTP/1.1 for the WebSocket
/// upgrade, HTTP/2 for gRPC, either for XHTTP).
@visibleForTesting
Map<String, dynamic> withCdnDial(
  Map<String, dynamic> config,
  String transport,
  CdnDial dial,
) {
  final List<String> alpn = switch (transport) {
    'websocket' => <String>['http/1.1'],
    'grpc' => <String>['h2'],
    _ => <String>['h2', 'http/1.1'],
  };
  return <String, dynamic>{
    ...config,
    'outbounds': <dynamic>[
      for (final dynamic outbound in config['outbounds'] as List<dynamic>)
        if (outbound is Map<String, dynamic> && outbound['tag'] == 'proxy')
          _dialled(outbound, alpn, dial)
        else
          outbound,
    ],
  };
}

Map<String, dynamic> _dialled(
  Map<String, dynamic> outbound,
  List<String> alpn,
  CdnDial dial,
) {
  final Map<String, dynamic> stream =
      outbound['streamSettings'] as Map<String, dynamic>;
  final Map<String, dynamic> tls = <String, dynamic>{
    ...stream['tlsSettings'] as Map<String, dynamic>,
  }..remove('echConfigList');
  final bool ff = dial == CdnDial.ff;
  return <String, dynamic>{
    ...outbound,
    'streamSettings': <String, dynamic>{
      ...stream,
      'tlsSettings': <String, dynamic>{
        ...tls,
        'fingerprint': ff ? 'unsafe' : 'chrome',
        'alpn': alpn,
        if (ff) 'cipherSuites': kSemiPythonCipherSuites,
      },
      if (ff)
        'finalmask': <String, dynamic>{
          'tcp': <Map<String, dynamic>>[
            <String, dynamic>{
              'type': 'fragment',
              'settings': <String, dynamic>{
                'packets': 'tlshello',
                'lengths': <String>['0', '104', '1'],
                'delays': <String>['0'],
                'maxSplit': '0',
              },
            },
            <String, dynamic>{
              'type': 'fragment',
              'settings': <String, dynamic>{
                'packets': '1-1',
                'lengths': <String>['114', '1'],
                'delays': <String>['1'],
                'maxSplit': '11',
              },
            },
          ],
        },
    },
  };
}

/// Hysteria2 does not run on Xray-core, so this renders a config for the
/// reference implementation instead -- which the Android side runs as a child
/// process, exposing SOCKS5 on the same local port tun2socks already dials.
///
/// Xray accepts Salamander obfuscation and silently discards it: a client
/// offering a deliberately wrong password authenticates successfully, so a
/// server configured for obfuscation has none, and a client applying real
/// Salamander cannot reach one that does. Measured against the live server;
/// see docs/adr/0003.
///
/// The YAML is carried inside a JSON envelope because the Android plugin
/// parses that JSON for the tunnel's DNS servers, its local SOCKS port and the
/// notification text. Keeping the envelope means none of that has to change.
String _renderHysteriaClientConfigJson(
  XrayClientResult result, {
  required LocalProxy localProxy,
  AdvancedSettings settings = AdvancedSettings.defaults,
}) {
  final Map<String, dynamic> envelope = <String, dynamic>{
    'nebulaHysteriaConfig': _hysteriaYaml(result, localProxy),
    // Read by the plugin into VpnService.Builder.addDnsServer. Absent, Android
    // falls back to the underlying network's resolver -- which on the network
    // this exists to serve forges answers, sending a client to a blockpage
    // address before any tunnelled connection is attempted.
    'dns': dnsModuleFor(result, settings),
    // The port tun2socks dials, and therefore the port the child process must
    // listen on. The two are kept in step by both reading [localProxy].
    'inbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'tag': 'socks-in',
        'listen': '127.0.0.1',
        'port': localProxy.port,
        'protocol': 'socks',
        // Never served by Xray on this path, but read by the plugin: it is
        // where tun2socks learns the credentials the child process demands.
        'settings': _localSocksSettings(localProxy),
      },
    ],
    // Never started -- Xray is not running in this mode. Present because the
    // plugin's notification parser reads the server address and port from
    // here, and throws if the shape is missing.
    'outbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'protocol': 'hysteria',
        'settings': <String, dynamic>{
          'servers': <Map<String, dynamic>>[
            <String, dynamic>{
              'address': result.serverAddress,
              'port': result.port,
            },
          ],
        },
      },
    ],
  };
  return jsonEncode(envelope);
}

/// Ad blocking is not applied here. On the Xray path it is two layers, a DNS
/// module and a routing rule to a blackhole; the reference Hysteria2 client
/// has no equivalent routing engine, so only the DNS layer above survives.
/// Stated rather than left implicit because an ad-block profile on this
/// transport really does filter less than the same profile on the others.
String _hysteriaYaml(XrayClientResult result, LocalProxy localProxy) {
  final StringBuffer buffer = StringBuffer()
    ..writeln('server: ${result.serverAddress}:${result.port}')
    // The client UUID is the whole credential; the server renders it as both
    // username and password in its own userpass map.
    ..writeln('auth: ${result.uuid}:${result.uuid}')
    ..writeln('tls:')
    ..writeln('  sni: ${result.sni}')
    // Verification stays on: the server presents a real certificate for this
    // name, so accepting any certificate here would give up the only thing
    // stopping an interceptor from impersonating it.
    ..writeln('  insecure: false');
  final String? obfsPassword = result.obfsPassword;
  if (obfsPassword != null) {
    buffer
      ..writeln('obfs:')
      ..writeln('  type: salamander')
      ..writeln('  salamander:')
      ..writeln('    password: $obfsPassword');
  }
  buffer
    ..writeln('socks5:')
    ..writeln('  listen: 127.0.0.1:${localProxy.port}')
    // Quoted: an all-digit value would otherwise be read as a number.
    ..writeln('  username: "${localProxy.username}"')
    ..writeln('  password: "${localProxy.password}"');
  return buffer.toString();
}

/// The local SOCKS5 inbound's settings, the same on both engines.
///
/// Password authentication, never `noauth`: loopback is reachable by every
/// app on the phone. The plugin reads these back out of the config to start
/// tun2socks with them.
Map<String, dynamic> _localSocksSettings(LocalProxy localProxy) {
  return <String, dynamic>{
    'auth': 'password',
    'accounts': <Map<String, dynamic>>[
      <String, dynamic>{
        'user': localProxy.username,
        'pass': localProxy.password,
      },
    ],
    'udp': true,
  };
}

/// Ad-serving and mobile-ad-SDK domains routed to the blackhole outbound.
///
/// `domain:` matches the name and every subdomain, so one entry covers the
/// per-region and per-shard hostnames these networks actually serve from.
///
/// Deliberately excludes anything an app needs to function rather than to
/// monetize -- the failure mode of over-blocking here is not a missing
/// banner, it is an app that hangs on a request that never completes.
///
/// Also deliberately excludes pure analytics (google-analytics.com,
/// scorecardresearch.com and the like), which was a mistake worth undoing:
/// blocking them removes no advertising at all, while being precisely what
/// anti-adblock scripts probe for. They cost real availability -- sites
/// refusing to load until the "blocker" is off -- to buy nothing a user
/// would notice. Blocking here stays scoped to domains that actually serve
/// ads.
const List<String> _adBlockDomains = <String>[
  'domain:doubleclick.net',
  'domain:googlesyndication.com',
  'domain:googleadservices.com',
  'domain:adservice.google.com',
  'domain:amazon-adsystem.com',
  'domain:adnxs.com',
  'domain:adsrvr.org',
  'domain:criteo.com',
  'domain:criteo.net',
  'domain:pubmatic.com',
  'domain:rubiconproject.com',
  'domain:openx.net',
  'domain:casalemedia.com',
  'domain:smartadserver.com',
  'domain:taboola.com',
  'domain:outbrain.com',
  'domain:moatads.com',
  'domain:adcolony.com',
  'domain:applovin.com',
  'domain:mopub.com',
  'domain:inmobi.com',
  'domain:chartboost.com',
  'domain:vungle.com',
  'domain:startappservice.com',
  'domain:flurry.com',
  'domain:unityads.unity3d.com',
];

/// Same resolver (and same provider) as provisioning/service.py's
/// `_AD_BLOCK_DNS_SERVER` for WireGuard -- AdGuard DNS's default filtering
/// blocks ads, trackers, and known malware/phishing domains at resolution
/// time.
/// IPv4 only, deliberately -- see [_plainDnsModule] for why.
const Map<String, dynamic> _adBlockDnsModule = <String, dynamic>{
  'servers': <String>['94.140.14.14'],
};

/// AdGuard's explicitly non-filtering resolver, for profiles that are not
/// ad-blocking.
///
/// Deliberately still a declared resolver rather than none: leaving it unset
/// hands DNS to whatever network the device is on, which on a hostile one
/// means the operator both observes and forges it. Deliberately the same
/// provider as the ad-block resolver above so the only difference between the
/// two profiles is filtering, and deliberately their *non-filtering* endpoint
/// rather than a general public resolver, so a plain profile is genuinely
/// unfiltered instead of quietly inheriting somebody's blocklist.
/// IPv4 only. Under badvpn's tun2socks, which carried no IPv6, an IPv6
/// resolver sent lookups into a tunnel that dropped them (measured on a
/// phone: the VPN's `ValidatedPrivateDnsAddresses` listed only the v4 one,
/// every lookup paying for the attempt). hev-socks5-tunnel does carry IPv6
/// -- a phone's IPv6 went out at the server's address on 2026-10-14 -- and
/// the resolver is reached over the tunnel either way, so v4 still answers
/// AAAA questions; nothing is gained by adding a v6 address here.
const Map<String, dynamic> _plainDnsModule = <String, dynamic>{
  'servers': <String>['94.140.14.140'],
};

Map<String, dynamic> _vlessStreamSettings(XrayClientResult result) {
  final Map<String, dynamic> streamSettings = <String, dynamic>{
    'network': result.transport,
    'security': result.transportSecurity,
  };
  switch (result.transport) {
    case 'xhttp':
      streamSettings['xhttpSettings'] = <String, dynamic>{'path': result.path};
    case 'grpc':
      streamSettings['grpcSettings'] = <String, dynamic>{
        'serviceName': result.serviceName,
      };
    case 'websocket':
      streamSettings['wsSettings'] = <String, dynamic>{'path': result.path};
    // 'raw' needs no per-transport settings block at all.
  }
  if (result.transportSecurity == 'reality') {
    // REALITY presents another site's certificate and proves the server by
    // its key instead; there is no certificate of its own to check.
    streamSettings['realitySettings'] = <String, dynamic>{
      'serverName': result.sni,
      'fingerprint': result.fingerprint ?? 'chrome',
      'publicKey': result.realityPublicKey,
      'shortId': result.realityShortId ?? '',
      'spiderX': '',
    };
  }
  // Only TLS profiles carry a TLS server name -- an unencrypted transport
  // (transportSecurity == 'none', XHTTP's nginx-fronted case) has nothing
  // for tlsSettings to configure.
  if (result.transportSecurity == 'tls') {
    final String? ca = result.caCertificate;
    streamSettings['tlsSettings'] = <String, dynamic>{
      'serverName': result.sni,
      // An installation with its own CA (reached by IP) sends it, and the
      // tunnel is verified against it, as the API is. Without it Xray checks
      // only the system's roots, the handshake fails, and the app says
      // Protected while nothing moves -- seen on a phone against such an
      // install. Verification stays on either way.
      //
      // And against it alone: disableSystemRoot stops Xray also accepting
      // any publicly trusted certificate for this address, so the tunnel
      // trusts exactly what pairing pinned -- as the API client does.
      // What the network sees: Chrome's handshake rather than Xray's
      // default one, which DPI can single out. Not for an installation with
      // its own CA, reached by address on a network of its own, where there
      // is nobody to hide from.
      if (ca == null) 'fingerprint': result.fingerprint ?? 'chrome',
      if (echConfigListFor(result) case final String ech) 'echConfigList': ech,
      if (ca != null) ...<String, dynamic>{
        'disableSystemRoot': true,
        'certificates': <Map<String, dynamic>>[
          <String, dynamic>{
            'usage': 'verify',
            'certificate': const LineSplitter().convert(ca.trim()),
          },
        ],
      },
    };
  }
  return streamSettings;
}

/// Encrypted Client Hello for a tunnel through Cloudflare, or null.
///
/// Measured from Iran on 2026-10-07, on a home line and on Hamrah-e-Avval
/// mobile data: WebSocket, XHTTP and gRPC through Cloudflare -- a free
/// relay on `workers.dev` too -- carried nothing over HTTPS without it and
/// everything with it, and the hello written in pieces that got a relay
/// through on 2026-10-02 no longer did. With ECH the name the network sees is
/// Cloudflare's shared `cloudflare-ech.com`, not the route's own.
///
/// The server says so for its CDN route ([XrayClientResult.echConfigList]);
/// a free relay is known by its name.
///
/// Its lookup server is the one that answered at the last check
/// ([refreshEchServer]), when the route asked for one of ours.
String? echConfigListFor(XrayClientResult result) {
  final String? ech =
      result.echConfigList ??
      (result.sni.toLowerCase().endsWith('.workers.dev')
          ? kCloudflareEch
          : null);
  return ech == null ? null : withWorkingEchServer(ech);
}

/// Cloudflare's ECH key, looked up under its public name through 1.1.1.1.
const String kCloudflareEch = 'cloudflare-ech.com+udp://1.1.1.1';

Map<String, dynamic> _vlessOutbound(XrayClientResult result) {
  return <String, dynamic>{
    // The name the plugin queries counters under. Not cosmetic: an untagged
    // outbound gets a generated name, `queryStats("proxy", ...)` matches
    // nothing, and the screen reads zero forever.
    'tag': 'proxy',
    'protocol': result.protocol,
    'settings': switch (result.protocol) {
      // `servers` for both, as Xray-core's own Trojan and Shadowsocks
      // outbounds take them.
      'trojan' => <String, dynamic>{
        'servers': <Map<String, dynamic>>[
          <String, dynamic>{
            'address': result.serverAddress,
            'port': result.port,
            'password': result.password,
          },
        ],
      },
      'shadowsocks' => <String, dynamic>{
        'servers': <Map<String, dynamic>>[
          <String, dynamic>{
            'address': result.serverAddress,
            'port': result.port,
            'method': result.method,
            'password': result.password,
          },
        ],
      },
      'vmess' => <String, dynamic>{
        'vnext': <Map<String, dynamic>>[
          <String, dynamic>{
            'address': result.serverAddress,
            'port': result.port,
            'users': <Map<String, dynamic>>[
              <String, dynamic>{'id': result.uuid, 'security': 'auto'},
            ],
          },
        ],
      },
      _ => <String, dynamic>{
        'vnext': <Map<String, dynamic>>[
          <String, dynamic>{
            'address': result.serverAddress,
            'port': result.port,
            'users': <Map<String, dynamic>>[
              <String, dynamic>{
                'id': result.uuid,
                'encryption': result.encryption ?? 'none',
                'flow': ?result.flow,
              },
            ],
          },
        ],
      },
    },
    'streamSettings': _vlessStreamSettings(result),
  };
}

/// Hysteria2 runs over QUIC and always terminates TLS itself -- there is no
/// unencrypted variant, and the handshake requires the `h3` ALPN token
/// (matches services/vpn-agent's own server-side inbound rendering).
Map<String, dynamic> _hysteriaOutbound(XrayClientResult result) {
  return <String, dynamic>{
    'protocol': 'hysteria',
    'settings': <String, dynamic>{
      'version': 2,
      'address': result.serverAddress,
      'port': result.port,
      // `flutter_v2ray_client`'s own Java-side Utilities.parseV2rayJsonFile
      // (used only to populate its connected-server notification text, not
      // to configure the tunnel) unconditionally tries
      // outbounds[0].settings.vnext[0] first, then falls back to
      // outbounds[0].settings.servers[0] on any exception -- with neither
      // present for Xray-core's real (flat address/port) Hysteria outbound
      // schema, the fallback itself throws JSONException uncaught, aborting
      // the whole start attempt before the tunnel ever comes up (confirmed
      // live: "No value for servers" at Utilities.java:107). This redundant
      // `servers` array exists purely to satisfy that parser -- Xray-core
      // itself ignores the extra unrecognized field.
      'servers': <Map<String, dynamic>>[
        <String, dynamic>{'address': result.serverAddress, 'port': result.port},
      ],
    },
    'streamSettings': <String, dynamic>{
      'network': 'hysteria',
      'security': 'tls',
      'tlsSettings': <String, dynamic>{
        'serverName': result.sni,
        'alpn': <String>['h3'],
      },
      'hysteriaSettings': <String, dynamic>{'version': 2, 'auth': result.uuid},
      // Salamander obfuscation (Xray-core's `udpmasks` finalmask, a
      // top-level streamSettings field, NOT part of hysteriaSettings) --
      // without this, plain QUIC/Hysteria2 handshakes are fingerprintable
      // and get silently dropped by some ISPs (confirmed live: packets
      // reached the server's firewall fine but the handshake never
      // completed until this was added). Only set when the server actually
      // configured an obfs password for this inbound.
      if (result.obfsPassword != null)
        'udpmasks': <Map<String, dynamic>>[
          <String, dynamic>{
            'type': 'salamander',
            'settings': <String, dynamic>{'password': result.obfsPassword},
          },
        ],
    },
  };
}

/// The resolvers the tunnel declares.
///
/// A chosen list wins over the profile's own, because somebody who typed a
/// resolver in did so to override exactly this. With nothing chosen the
/// shipped behaviour stands: AdGuard's filtering resolver for an ad-block
/// profile, its non-filtering one otherwise.
///
/// Never empty either way. `flutter_v2ray_client` turns this block into the
/// tunnel's own DNS servers, and an absent one does not mean "no DNS" -- it
/// means Android falls back to the underlying network's resolver, which on
/// the networks this app exists for both observes and forges it.
Map<String, dynamic> dnsModuleFor(
  XrayClientResult result,
  AdvancedSettings settings,
) {
  final List<String> chosen = settings.dnsServers
      .where((String server) => !_isIpv6Literal(server))
      .toList(growable: false);
  if (chosen.isNotEmpty) {
    return <String, dynamic>{'servers': chosen};
  }
  // Falling through to the profile's own resolver rather than returning an
  // empty list: no resolver at all does not mean "no DNS", it means the
  // network's own, which on the networks this app exists for both observes
  // and forges it. That is the worse outcome of the two, so a list that was
  // entirely IPv6 is treated as no choice rather than as a choice of nothing.
  if (result.adBlock) {
    return _adBlockDnsModule;
  }
  // Then the deployment's own choice, made by its operator at install. The
  // built-in resolver is only for a server too old to say.
  final List<String> deployment = result.clientDns
      .where((String server) => !_isIpv6Literal(server))
      .toList(growable: false);
  return deployment.isNotEmpty
      ? <String, dynamic>{'servers': deployment}
      : _plainDnsModule;
}

/// Whether a typed resolver is an IPv6 address.
///
/// Dropped rather than passed through, for the reason in [_plainDnsModule]:
/// one IPv6 resolver in this list is what makes Android route the whole
/// family into a tunnel that cannot carry it. A colon is enough to tell --
/// this list holds addresses, never host:port pairs or names.
bool _isIpv6Literal(String server) => server.contains(':');

/// Whether to read hostnames out of connections.
///
/// The default reproduces what the app has always done rather than picking a
/// side: on where a profile has domain rules to feed, off where it has none.
bool sniffingEnabledFor(XrayClientResult result, AdvancedSettings settings) {
  // Sanctions routing is nothing but a domain rule. Without a hostname every
  // connection would fall through to the direct rule, so the tunnel would be
  // up and carry nothing -- which is why it overrides even "never". Sites
  // that skip the VPN are domain rules too.
  if (routesAnythingDirect(result, settings)) {
    return true;
  }
  return switch (settings.sniffing) {
    SniffingMode.always => true,
    SniffingMode.never => false,
    SniffingMode.whenRoutingNeedsIt => result.adBlock,
  };
}

/// Whether any traffic of this connection leaves directly rather than
/// through the server: sanctions-only routing, websites that skip the VPN,
/// or Iranian addresses. Xray profiles only -- Hysteria2 has no routing.
bool routesAnythingDirect(XrayClientResult result, AdvancedSettings settings) {
  return routesSanctionsOnly(result, settings) ||
      (result.transport != 'hysteria' &&
          (settings.bypassDomains.isNotEmpty || settings.iranDirect));
}

/// Whether a settings change alters which traffic goes through the server,
/// so a running connection has to be rebuilt for it to apply.
bool routingChanged(AdvancedSettings before, AdvancedSettings after) =>
    before.routingMode != after.routingMode ||
    before.iranDirect != after.iranDirect ||
    !listEquals(before.bypassDomains, after.bypassDomains);

/// Whether Iranian addresses and websites leave directly.
bool routesIranDirect(XrayClientResult result, AdvancedSettings settings) {
  return settings.iranDirect && result.transport != 'hysteria';
}

/// Whether this connection sends only sanctioned services to the server.
///
/// Xray profiles only. Hysteria2 runs on a different client with no domain
/// routing, so on it the mode does not apply and everything is tunnelled --
/// the safe direction to fail in, since it is still a working VPN.
bool routesSanctionsOnly(XrayClientResult result, AdvancedSettings settings) {
  return settings.routingMode == RoutingMode.sanctionedOnly &&
      result.transport != 'hysteria';
}

/// Adds multiplexing to an outbound, or leaves it exactly as it was.
///
/// Absent rather than `enabled: false` when off, so a default install
/// generates byte-for-byte the config it generated before this setting
/// existed -- which is what makes "I changed nothing and it broke" a
/// question with an answer.
/// Whether a VLESS outbound uses VLESS Encryption. Mux's UDP (XUDP) over it
/// lost DNS answers -- 1 of 3 through, against 3 of 3 without mux, measured
/// from the home line on 2026-10-23 -- and the tunnel check then reported a
/// working connection as dead. VLESS carries each UDP flow itself instead.
bool _vlessEncrypted(Map<String, dynamic> outbound) {
  final Object? settings = outbound['settings'];
  if (outbound['protocol'] != 'vless' || settings is! Map<String, dynamic>) {
    return false;
  }
  final Object? vnext = settings['vnext'];
  if (vnext is! List<dynamic> || vnext.isEmpty) {
    return false;
  }
  final Object? users = (vnext.first as Map<String, dynamic>)['users'];
  if (users is! List<dynamic> || users.isEmpty) {
    return false;
  }
  final Object? encryption =
      (users.first as Map<String, dynamic>)['encryption'];
  return encryption is String && encryption != 'none';
}

Map<String, dynamic> _withMux(
  Map<String, dynamic> outbound,
  AdvancedSettings settings,
) {
  // Vision handles its own framing; Xray refuses it inside Mux. Mux.Cool is
  // VLESS's and Trojan's; Shadowsocks carries UDP on its own.
  final bool vision = outbound.toString().contains('xtls-rprx-vision');
  if (vision ||
      _vlessEncrypted(outbound) ||
      !<String>{'vless', 'trojan'}.contains(outbound['protocol'])) {
    return outbound;
  }
  return <String, dynamic>{
    ...outbound,
    'mux': <String, dynamic>{
      'enabled': true,
      // TCP one connection each unless asked: muxed, it is more distinctive
      // and holds every page behind one stalled stream.
      'concurrency': settings.muxEnabled ? settings.muxConcurrency : -1,
      // Every UDP flow -- every app's DNS -- over one connection instead of
      // a new one each. Over the CDN with WebSocket a lookup went from 0.54 s
      // to 0.15 s and a fresh HTTPS connection from 1.26 s to 0.50 s
      // (measured from Iran, 2026-10-14).
      'xudpConcurrency': 16,
      // QUIC refused, so apps fall straight back to TCP, which a tunnel over
      // TCP carries far better than QUIC inside it.
      'xudpProxyUDP443': 'reject',
    },
  };
}

/// The outbound that actually does the splitting.
///
/// A plain `freedom` outbound whose only job is to write the bytes it is
/// handed in pieces. The proxy outbound then dials *through* it, which is why
/// this is a second outbound rather than a field on the first: fragmenting is
/// a property of how the connection is written to the socket, and the proxy
/// outbound does not own that step.
Map<String, dynamic> fragmentOutbound(FragmentSettings fragment) {
  return <String, dynamic>{
    'tag': _fragmentTag,
    'protocol': 'freedom',
    'settings': <String, dynamic>{
      'fragment': <String, dynamic>{
        'packets': fragment.packets,
        'length': fragment.length,
        'interval': fragment.interval,
      },
    },
  };
}

/// Points an outbound at the fragmenting one, or leaves it exactly as it was.
///
/// `dialerProxy` rather than a routing rule: a rule would send the *traffic*
/// through another outbound, which is a proxy chain. This says "when you open
/// the socket, open it through that one" -- the connection still goes to the
/// same server, it is just written differently.
///
/// Untouched when off, so a default install generates byte for byte the
/// config it generated before this setting existed.
Map<String, dynamic> _withFragment(
  Map<String, dynamic> outbound,
  AdvancedSettings settings,
) {
  if (!settings.fragment.enabled) {
    return outbound;
  }
  final Map<String, dynamic> streamSettings = <String, dynamic>{
    ...?(outbound['streamSettings'] as Map<String, dynamic>?),
  };
  final Map<String, dynamic> sockopt = <String, dynamic>{
    ...?(streamSettings['sockopt'] as Map<String, dynamic>?),
    'dialerProxy': _fragmentTag,
  };
  streamSettings['sockopt'] = sockopt;
  return <String, dynamic>{...outbound, 'streamSettings': streamSettings};
}

const String _fragmentTag = 'fragment';

/// The core's logging, both halves of it.
///
/// `loglevel` governs the *error* log only. The access log is a separate
/// key, and with it unset the core writes a line per connection naming the
/// address it went to -- so every site a person visits was landing in
/// logcat, at any log level, including the `warning` this app has always
/// asked for. Found by reading the connection-log screen on a real phone
/// while the screen beside it said nothing about what you visit is recorded.
///
/// Turned off, except when somebody has explicitly chosen a level that
/// records destinations. Those two options say plainly that they do; every
/// other one now tells the truth.
Map<String, dynamic> logModuleFor(AdvancedSettings settings) {
  return <String, dynamic>{
    'loglevel': settings.logLevel.wireName,
    // `none` is the core's own way of saying "do not keep one", and is not
    // the same as an empty path, which it would treat as a filename.
    if (!settings.logLevel.recordsDestinations) 'access': 'none',
  };
}

/// The transports that can cross a CDN, and so the only ones a clean
/// Cloudflare address applies to.
const Set<String> cdnTransports = <String>{'xhttp', 'websocket', 'grpc'};
