import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/xray/windows_tunnel_config.dart';

void main() {
  _killSwitchRanges();

  const String profile = '''server: vpn.example.org:8450
auth: test-credential
tls:
  sni: vpn.example.org
  insecure: false
''';

  test(
    'all IPv4 and IPv6 traffic is captured with only transport excluded',
    () {
      final String config = windowsHysteriaFullTunnelConfig(
        profile,
        '203.0.113.4',
      );
      expect(config, contains('server: 203.0.113.4:8450'));
      expect(config, contains('sni: vpn.example.org'));
      expect(config, contains('insecure: false'));
      expect(config, contains('ipv4: [0.0.0.0/0]'));
      expect(config, contains('ipv6: ["::/0"]'));
      expect(config, contains('ipv4Exclude: [203.0.113.4/32]'));
      expect(config, isNot(contains('youtube')));
    },
  );

  test('missing numeric upstream fails instead of allowing a route loop', () {
    expect(
      () => windowsHysteriaFullTunnelConfig(profile, ''),
      throwsStateError,
    );
    expect(
      () => windowsHysteriaFullTunnelConfig(profile, 'vpn.example.org'),
      throwsStateError,
    );
    expect(
      () => windowsHysteriaFullTunnelConfig('auth: secret', '203.0.113.4'),
      throwsStateError,
    );
  });

  test(
    'Windows preserves profile DNS including ad-block and custom choices',
    () {
      for (final String ip in <String>[
        '94.140.14.140',
        '94.140.14.14',
        '1.1.1.1',
      ]) {
        expect(
          windowsTunnelDnsServers(<String, dynamic>{
            'dns': <String, dynamic>{
              'servers': <String>[ip],
            },
          }),
          <String>[ip],
        );
      }
      expect(
        () => windowsTunnelDnsServers(<String, dynamic>{}),
        throwsStateError,
      );
      expect(
        () => windowsTunnelDnsServers(<String, dynamic>{
          'dns': <String, dynamic>{
            'servers': <String>['resolver; injected'],
          },
        }),
        throwsStateError,
      );
    },
  );

  test('helper command preserves spaces, apostrophes and Unicode', () {
    final String quoted = windowsPowerShellLiteral(
      "C:\\Users\\Test O'Name\\VPN فارسی\\config.yaml",
    );
    expect(quoted, "'C:\\Users\\Test O''Name\\VPN فارسی\\config.yaml'");
    final List<int> bytes = base64Decode(windowsEncodedCommand(quoted));
    expect(
      String.fromCharCodes(<int>[
        for (int i = 0; i < bytes.length; i += 2) bytes[i] | bytes[i + 1] << 8,
      ]),
      quoted,
    );
  });

  group('Xray full tunnel', () {
    // Measured on a laptop: with the server named by hostname, Xray looked it
    // up through Windows DNS, which the tunnel sends into the tunnel. Nothing
    // went anywhere while the app said Protected.
    final Map<String, dynamic> config = <String, dynamic>{
      'dns': <String, dynamic>{
        'servers': <String>['tcp://94.140.14.140'],
      },
      'outbounds': <Map<String, dynamic>>[
        <String, dynamic>{
          'tag': 'proxy',
          'protocol': 'vless',
          'settings': <String, dynamic>{
            'vnext': <Map<String, dynamic>>[
              <String, dynamic>{'address': 'cdn.example.org', 'port': 443},
            ],
          },
          'streamSettings': <String, dynamic>{
            'network': 'grpc',
            'tlsSettings': <String, dynamic>{'serverName': 'cdn.example.org'},
          },
        },
        <String, dynamic>{'tag': 'dns-out', 'protocol': 'dns'},
      ],
    };

    test('resolves its server to the address the app pinned', () {
      final Map<String, dynamic> pinned = windowsXrayPinnedUpstream(
        config,
        'cdn.example.org',
        '104.16.1.1',
      );
      final Map<String, dynamic> dns = pinned['dns'] as Map<String, dynamic>;
      expect(dns['hosts'], <String, dynamic>{'cdn.example.org': '104.16.1.1'});
      expect(dns['servers'], <String>['tcp://94.140.14.140']);
      final Map<String, dynamic> proxy =
          (pinned['outbounds'] as List<dynamic>).first as Map<String, dynamic>;
      final Map<String, dynamic> stream =
          proxy['streamSettings'] as Map<String, dynamic>;
      expect(stream['sockopt'], <String, dynamic>{'domainStrategy': 'UseIPv4'});
      // The hostname stays for TLS and the headers Cloudflare routes on.
      expect(jsonEncode(proxy), contains('"address":"cdn.example.org"'));
      expect(stream['network'], 'grpc');
      expect((pinned['outbounds'] as List<dynamic>)[1], <String, dynamic>{
        'tag': 'dns-out',
        'protocol': 'dns',
      });
    });

    test('a server named by address is left alone', () {
      expect(
        windowsXrayPinnedUpstream(config, '104.16.1.1', '104.16.1.1'),
        same(config),
      );
    });
  });

  test("the full tunnel asks the profile's resolvers, not a fixed one", () {
    final Map<String, dynamic> tun = windowsXrayTunConfig(<String, dynamic>{
      'dns': <String, dynamic>{
        'servers': <String>['9.9.9.9', '1.1.1.1'],
      },
      'outbounds': <Map<String, dynamic>>[
        <String, dynamic>{'tag': 'proxy', 'protocol': 'vless'},
      ],
    });

    final Map<String, dynamic> dns = tun['dns'] as Map<String, dynamic>;
    expect(dns['servers'], <String>['tcp://9.9.9.9', 'tcp://1.1.1.1']);
    final Map<String, dynamic> inbound =
        (tun['inbounds'] as List<dynamic>).single as Map<String, dynamic>;
    expect((inbound['settings'] as Map<String, dynamic>)['dns'], <String>[
      '9.9.9.9',
      '1.1.1.1',
    ]);
    expect(jsonEncode(tun), isNot(contains('94.140.14.140')));
  });

  test('"Allow local network" sends private addresses out directly', () {
    final Map<String, dynamic> source = <String, dynamic>{
      'dns': <String, dynamic>{
        'servers': <String>['9.9.9.9'],
      },
      'outbounds': <Map<String, dynamic>>[
        <String, dynamic>{'tag': 'proxy', 'protocol': 'vless'},
      ],
      'routing': <String, dynamic>{
        'rules': <Map<String, dynamic>>[
          <String, dynamic>{'type': 'field', 'outboundTag': 'proxy'},
        ],
      },
    };
    final Map<String, dynamic> tun = windowsXrayTunConfig(
      source,
      localNetworkDirect: true,
    );

    final List<dynamic> rules =
        (tun['routing'] as Map<String, dynamic>)['rules'] as List<dynamic>;
    final int local = rules.indexWhere((dynamic r) {
      final Object? ip = (r as Map<String, dynamic>)['ip'];
      return ip is List<dynamic> && ip.contains('geoip:private');
    });
    // Ahead of the profile's own rules, so nothing sends them to the server.
    expect(local, lessThan(rules.length - 1));
    final String tag =
        (rules[local] as Map<String, dynamic>)['outboundTag'] as String;
    expect(
      (tun['outbounds'] as List<dynamic>).any(
        (dynamic o) =>
            (o as Map<String, dynamic>)['tag'] == tag &&
            o['protocol'] == 'freedom',
      ),
      isTrue,
    );
    expect(
      jsonEncode(windowsXrayTunConfig(source)),
      isNot(contains('geoip:private')),
    );
  });
}

void _killSwitchRanges() {
  bool blocked(List<String> ranges, String ip) {
    int n(String a) =>
        a.split('.').map(int.parse).fold(0, (int v, int o) => (v << 8) | o);
    return ranges.any((String r) {
      final List<String> ends = r.split('-');
      return n(ends[0]) <= n(ip) && n(ip) <= n(ends[1]);
    });
  }

  test('the kill switch blocks the internet but not the server or the LAN', () {
    final List<String> ranges = windowsKillSwitchBlockedIpv4('203.0.113.4');
    for (final String ip in <String>[
      '1.1.1.1',
      '8.8.8.8',
      '203.0.113.3',
      '203.0.113.5',
      '172.32.0.1',
      '240.0.0.1',
    ]) {
      expect(blocked(ranges, ip), isTrue, reason: ip);
    }
    for (final String ip in <String>[
      '203.0.113.4',
      '10.1.2.3',
      '192.168.1.1',
      '172.16.5.5',
      '169.254.1.1',
      '127.0.0.1',
      '224.0.0.251',
      '255.255.255.255',
    ]) {
      expect(blocked(ranges, ip), isFalse, reason: ip);
    }
    expect(ranges.first, '1.0.0.0-9.255.255.255');
    expect(ranges.last, '240.0.0.0-255.255.255.254');
  });
}
