/// The firewall mark Xray puts on its own connections on Linux, and the
/// routing table the tunnel's default route lives in.
///
/// Policy routing, as wg-quick does a full tunnel: everything without this
/// mark goes to the tunnel's table, and Xray's own connections -- to the
/// server, through a CDN whose address changes, for a "direct" rule -- carry
/// it and use the ordinary routes, so none of them can loop into the tunnel
/// they make. Pinning the server's one address around the tunnel, as Windows
/// does, would miss all but the first.
const int linuxTunnelMark = 51888;

/// The Linux interface the tunnel's engine creates.
const String linuxTunnelInterface = 'nebula';

/// The full-device tunnel around a rendered Xray client config on Linux.
///
/// As on Windows, DNS is answered by Xray itself through the proxy from the
/// profile's own resolvers. Unlike Windows, Xray's TUN on Linux sets up no
/// address and no routes of its own (`autoSystemRoutingTable` is Windows
/// only; measured), so the root helper does that; this marks every outbound
/// so the helper's routing can tell Xray's own traffic apart.
Map<String, dynamic> linuxXrayTunConfig(
  Map<String, dynamic> config,
  List<String> resolvers,
) {
  final Map<String, dynamic> existingRouting =
      (config['routing'] as Map<String, dynamic>?) ?? <String, dynamic>{};
  final List<dynamic> existingRules =
      (existingRouting['rules'] as List<dynamic>?) ?? <dynamic>[];
  final List<dynamic> existingOutbounds =
      (config['outbounds'] as List<dynamic>?) ?? <dynamic>[];
  return <String, dynamic>{
    ...config,
    'dns': <String, dynamic>{
      ...((config['dns'] as Map<String, dynamic>?) ?? <String, dynamic>{}),
      'servers': <String>[for (final String ip in resolvers) 'tcp://$ip'],
      'tag': 'nebula-dns',
    },
    'inbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'tag': 'tun-in',
        'protocol': 'tun',
        'settings': <String, dynamic>{
          'name': linuxTunnelInterface,
          'mtu': 1500,
        },
      },
    ],
    'outbounds': <dynamic>[
      for (final dynamic outbound in <dynamic>[
        ...existingOutbounds,
        <String, dynamic>{'tag': 'dns-out', 'protocol': 'dns'},
      ])
        if (outbound is Map<String, dynamic>) _marked(outbound) else outbound,
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
        ...existingRules,
      ],
    },
  };
}

Map<String, dynamic> _marked(Map<String, dynamic> outbound) {
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
        'mark': linuxTunnelMark,
      },
    },
  };
}
