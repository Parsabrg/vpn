import 'dart:convert';
import 'dart:io';

/// The native engine receives a numeric endpoint so the address excluded from
/// the tunnel is exactly the address used for its transport. TLS SNI stays in
/// the original profile and certificate verification remains enabled.
///
/// Linux uses it too, with its own [interfaceName], [platform] (the name in
/// the messages) and no [route]: there Hysteria's own routing left eight
/// rules and a table behind every session (measured), so the root helper
/// routes it as it routes Xray, keeping the pinned server address out.
String windowsHysteriaFullTunnelConfig(
  String yaml,
  String upstreamIpv4, {
  String interfaceName = 'Nebula',
  String platform = 'Windows',
  bool route = true,
}) {
  final InternetAddress? address = InternetAddress.tryParse(upstreamIpv4);
  if (address == null || address.type != InternetAddressType.IPv4) {
    throw StateError('$platform could not resolve the VPN server address.');
  }
  final RegExp serverLine = RegExp(r'^server:\s*([^\r\n]+)', multiLine: true);
  final RegExpMatch? match = serverLine.firstMatch(yaml);
  if (match == null) {
    throw StateError('$platform received an invalid VPN server profile.');
  }
  final String value = match.group(1)!.trim();
  final int? port = int.tryParse(value.substring(value.lastIndexOf(':') + 1));
  if (port == null || port < 1 || port > 65535) {
    throw StateError('$platform received an invalid VPN server port.');
  }
  final String pinned = yaml.replaceFirst(
    serverLine,
    'server: $upstreamIpv4:$port',
  );
  return '''$pinned
tun:
  name: $interfaceName
  mtu: 1500
  address:
    ipv4: 100.100.100.101/30
    ipv6: fd00:19::1/126
${route ? '''  route:
    ipv4: [0.0.0.0/0]
    ipv6: ["::/0"]
    ipv4Exclude: [$upstreamIpv4/32]
''' : ''}''';
}

/// Hands Xray the server address the app already resolved, as the Hysteria2
/// path above does, while the config keeps the hostname -- TLS and the
/// gRPC/WebSocket headers need it, and Cloudflare routes on it.
///
/// Without this, Xray looked its own server up through Windows DNS, which
/// the tunnel sends into the tunnel: resolving the server needed the tunnel,
/// the tunnel needed the server, and Windows showed Protected while nothing
/// but failed lookups went anywhere. Measured on a laptop through Cloudflare.
Map<String, dynamic> windowsXrayPinnedUpstream(
  Map<String, dynamic> config,
  String host,
  String upstreamIpv4,
) {
  if (host == upstreamIpv4) {
    return config;
  }
  // An IPv6 edge address (CdnDial.ipv6) has to be dialled as one.
  final bool v6 = upstreamIpv4.contains(':');
  final Map<String, dynamic> dns =
      (config['dns'] as Map<String, dynamic>?) ?? <String, dynamic>{};
  final List<dynamic> outbounds =
      (config['outbounds'] as List<dynamic>?) ?? <dynamic>[];
  return <String, dynamic>{
    ...config,
    'dns': <String, dynamic>{
      ...dns,
      'hosts': <String, dynamic>{
        ...((dns['hosts'] as Map<String, dynamic>?) ?? <String, dynamic>{}),
        host: upstreamIpv4,
      },
    },
    'outbounds': <dynamic>[
      for (final dynamic outbound in outbounds)
        if (outbound is Map<String, dynamic> && outbound['tag'] == 'proxy')
          _resolvedByXray(outbound, v6 ? 'UseIPv6' : 'UseIPv4')
        else
          outbound,
    ],
  };
}

/// Makes the outbound resolve its server through Xray's own DNS -- and so
/// through the `hosts` entry -- instead of the system's.
Map<String, dynamic> _resolvedByXray(
  Map<String, dynamic> outbound,
  String strategy,
) {
  final Map<String, dynamic> stream =
      (outbound['streamSettings'] as Map<String, dynamic>?) ??
      <String, dynamic>{};
  return <String, dynamic>{
    ...outbound,
    'streamSettings': <String, dynamic>{
      ...stream,
      'sockopt': <String, dynamic>{
        ...((stream['sockopt'] as Map<String, dynamic>?) ??
            <String, dynamic>{}),
        'domainStrategy': strategy,
      },
    },
  };
}

/// The full-device tunnel around a rendered Xray client config: a TUN inbound
/// that carries everything, with DNS answered by Xray itself through the
/// proxy.
///
/// The resolvers are the profile's own -- the deployment's (from the server),
/// the ad-block one, or the person's choice in Advanced settings -- the same
/// list the Android tunnel uses. This used to be a fixed public resolver
/// whatever the profile said, so a deployment's DNS policy did not reach
/// Windows at all. Asked over TCP: a DNS query carried through the proxy as
/// UDP is what some transports cannot carry.
///
/// [localNetworkDirect] is "Allow local network": private and link-local
/// addresses (a NAS, a printer, a dev server on another machine, a work
/// network over 10.x) leave by the real network instead of the server. The
/// TUN still takes them -- its routes are fixed -- and Xray sends them out
/// directly, bound to the real interface like every direct outbound here.
Map<String, dynamic> windowsXrayTunConfig(
  Map<String, dynamic> config, {
  bool localNetworkDirect = false,
}) {
  final List<String> resolvers = windowsTunnelDnsServers(config);
  final Map<String, dynamic> existingRouting =
      (config['routing'] as Map<String, dynamic>?) ?? <String, dynamic>{};
  final List<dynamic> existingRules =
      (existingRouting['rules'] as List<dynamic>?) ?? <dynamic>[];
  final List<dynamic> existingOutbounds =
      (config['outbounds'] as List<dynamic>?) ?? <dynamic>[];
  return <String, dynamic>{
    ...config,
    'dns': <String, dynamic>{
      'servers': <String>[for (final String ip in resolvers) 'tcp://$ip'],
      'tag': 'nebula-dns',
    },
    'inbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'tag': 'tun-in',
        'protocol': 'tun',
        'settings': <String, dynamic>{
          'name': 'Nebula',
          'desc': 'Nebula VPN',
          'mtu': 1500,
          'gateway': <String>['172.19.0.1/30', 'fd00:19::1/64'],
          'dns': resolvers,
          'autoSystemRoutingTable': <String>['0.0.0.0/0', '::/0'],
          'autoOutboundsInterface': 'auto',
        },
      },
    ],
    'outbounds': <dynamic>[
      ...existingOutbounds,
      <String, dynamic>{'tag': 'dns-out', 'protocol': 'dns'},
      if (localNetworkDirect)
        <String, dynamic>{'tag': _localDirectTag, 'protocol': 'freedom'},
    ],
    'routing': <String, dynamic>{
      ...existingRouting,
      'rules': <dynamic>[
        <String, dynamic>{
          'type': 'field',
          'inboundTag': <String>['tun-in'],
          'port': '53',
          'outboundTag': 'dns-out',
        },
        <String, dynamic>{
          'type': 'field',
          'inboundTag': <String>['nebula-dns'],
          'outboundTag': 'proxy',
        },
        if (localNetworkDirect)
          <String, dynamic>{
            'type': 'field',
            'inboundTag': <String>['tun-in'],
            'ip': <String>['geoip:private'],
            'outboundTag': _localDirectTag,
          },
        ...existingRules,
      ],
    },
  };
}

const String _localDirectTag = 'local-direct';

/// Reuse the profile's normal/ad-block/custom DNS selection on Windows.
/// Passing these literal addresses to the elevated helper avoids any command
/// or hostname interpretation and makes resolver routes independently testable.
List<String> windowsTunnelDnsServers(Map<String, dynamic> source) {
  final dynamic dns = source['dns'];
  final dynamic configured = dns is Map ? dns['servers'] : null;
  final List<String> servers = <String>[];
  if (configured is List) {
    for (final dynamic value in configured) {
      if (value is! String || InternetAddress.tryParse(value) == null) {
        throw StateError('Windows VPN DNS servers must be IP addresses.');
      }
      servers.add(value);
    }
  }
  if (servers.isEmpty) {
    // Every config the app renders names its resolvers (see dnsModuleFor);
    // one that does not is not something to fill in with a guess.
    throw StateError('Windows VPN needs at least one DNS server.');
  }
  return servers;
}

/// Encode fixed helper arguments without Start-Process's lossy array joining.
/// Windows PowerShell -EncodedCommand accepts UTF-16LE.
String windowsEncodedCommand(String command) {
  return base64Encode(<int>[
    for (final int unit in command.codeUnits) ...<int>[unit & 255, unit >> 8],
  ]);
}

String windowsPowerShellLiteral(String value) =>
    "'${value.replaceAll("'", "''")}'";

/// The Start-Process call that runs PowerShell with [powershellArguments]
/// as administrator, by way of this app's own executable.
///
/// It used to ask for powershell.exe, and Windows' permission prompt said
/// "Windows PowerShell", with PowerShell's icon, which reads like something
/// other than this app asking. The runner (windows/runner/main.cpp) starts
/// the same hidden PowerShell when given `--nebula-elevated`, so the prompt
/// names Nebula VPN. Callers add -Wait and -PassThru as they need them.
String windowsElevatedLaunch(
  String powershellArguments, {
  String? executable,
}) =>
    'Start-Process -FilePath '
    '${windowsPowerShellLiteral(executable ?? Platform.resolvedExecutable)} '
    '-ArgumentList ${windowsPowerShellLiteral('--nebula-elevated $powershellArguments')} '
    '-Verb RunAs -WindowStyle Hidden';

/// The IPv4 address [config] already pins [host] to -- a clean Cloudflare
/// address the person chose -- so the tunnel's own resolving keeps it rather
/// than replacing it with whatever DNS says.
String? pinnedUpstream(Map<String, dynamic> config, String? host) {
  if (host == null) {
    return null;
  }
  final Object? dns = config['dns'];
  final Object? hosts = dns is Map<String, dynamic> ? dns['hosts'] : null;
  final Object? value = hosts is Map<String, dynamic> ? hosts[host] : null;
  if (value is! String) {
    return null;
  }
  final InternetAddress? address = InternetAddress.tryParse(value);
  return address != null && address.type == InternetAddressType.IPv4
      ? value
      : null;
}

/// The IPv4 ranges the Windows kill switch blocks on the real adapters:
/// every address except the VPN server's, the local network, loopback,
/// link-local, multicast and broadcast. Windows Firewall block rules cannot
/// say "all but", so the rest is written out as ranges.
List<String> windowsKillSwitchBlockedIpv4(String upstreamIpv4) {
  int parse(String ip) => ip
      .split('.')
      .map(int.parse)
      .fold(0, (int value, int octet) => (value << 8) | octet);
  String show(int value) => <int>[
    value >> 24 & 255,
    value >> 16 & 255,
    value >> 8 & 255,
    value & 255,
  ].join('.');
  (int, int) cidr(String network, int bits) {
    final int start = parse(network);
    return (start, start + (1 << (32 - bits)) - 1);
  }

  final List<(int, int)> allowed = <(int, int)>[
    (parse(upstreamIpv4), parse(upstreamIpv4)),
    cidr('0.0.0.0', 8),
    cidr('10.0.0.0', 8),
    cidr('127.0.0.0', 8),
    cidr('169.254.0.0', 16),
    cidr('172.16.0.0', 12),
    cidr('192.168.0.0', 16),
    cidr('224.0.0.0', 4),
    cidr('255.255.255.255', 32),
  ]..sort(((int, int) a, (int, int) b) => a.$1.compareTo(b.$1));
  final List<String> blocked = <String>[];
  int next = 0;
  for (final (int start, int end) in allowed) {
    if (start > next) {
      blocked.add('${show(next)}-${show(start - 1)}');
    }
    if (end + 1 > next) {
      next = end + 1;
    }
  }
  if (next <= 0xFFFFFFFF) {
    blocked.add('${show(next)}-255.255.255.255');
  }
  return blocked;
}

/// The IPv6 the kill switch blocks: everything but link-local (fe80::/10)
/// and multicast (ff00::/8), which neighbour discovery needs.
const List<String> windowsKillSwitchBlockedIpv6 = <String>[
  '::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
  'fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
];
