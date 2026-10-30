import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/wireguard/linux_wireguard_tunnel.dart';
import 'package:nebula_mobile/core/xray/linux_tunnel_config.dart';
import 'package:nebula_mobile/core/xray/linux_vpn_supervisor.dart';
import 'package:nebula_mobile/core/xray/windows_tunnel_config.dart';

void main() {
  final Map<String, dynamic> source = <String, dynamic>{
    'dns': <String, dynamic>{
      'servers': <String>['1.1.1.1'],
    },
    'inbounds': <Map<String, dynamic>>[
      <String, dynamic>{'protocol': 'socks', 'port': 10808},
    ],
    'outbounds': <Map<String, dynamic>>[
      <String, dynamic>{
        'tag': 'proxy',
        'protocol': 'vless',
        'streamSettings': <String, dynamic>{
          'network': 'xhttp',
          'sockopt': <String, dynamic>{'tcpFastOpen': true},
        },
      },
      <String, dynamic>{'tag': 'direct', 'protocol': 'freedom'},
    ],
    'routing': <String, dynamic>{
      'rules': <Map<String, dynamic>>[
        <String, dynamic>{'type': 'field', 'outboundTag': 'direct'},
      ],
    },
  };

  test('every outbound carries the mark, so none loops into the tunnel', () {
    final Map<String, dynamic> config = linuxXrayTunConfig(source, <String>[
      '1.1.1.1',
      '8.8.8.8',
    ]);
    final List<Map<String, dynamic>> outbounds = _maps(config['outbounds']);
    expect(outbounds.map((Map<String, dynamic> o) => o['tag']), <String>[
      'proxy',
      'direct',
      'dns-out',
    ]);
    for (final Map<String, dynamic> outbound in outbounds) {
      expect(_sockopt(outbound)['mark'], linuxTunnelMark);
    }
    // Existing socket options survive.
    expect(_sockopt(outbounds.first)['tcpFastOpen'], true);
    expect(
      (outbounds.first['streamSettings'] as Map<String, dynamic>)['network'],
      'xhttp',
    );
  });

  test('the TUN replaces the local proxy and DNS goes through the proxy', () {
    final Map<String, dynamic> config = linuxXrayTunConfig(source, <String>[
      '1.1.1.1',
    ]);
    final List<Map<String, dynamic>> inbounds = _maps(config['inbounds']);
    expect(inbounds, hasLength(1));
    expect(inbounds.single['protocol'], 'tun');
    expect(
      (inbounds.single['settings'] as Map<String, dynamic>)['name'],
      linuxTunnelInterface,
    );
    expect((config['dns'] as Map<String, dynamic>)['servers'], <String>[
      'tcp://1.1.1.1',
    ]);
    final List<Map<String, dynamic>> rules = _maps(
      (config['routing'] as Map<String, dynamic>)['rules'],
    );
    expect(rules[0]['outboundTag'], 'dns-out');
    expect(rules[1]['inboundTag'], <String>['nebula-dns']);
    expect(rules[1]['outboundTag'], 'proxy');
    expect(rules[2]['outboundTag'], 'direct');
  });

  test(
    'the root helper is valid bash',
    () async {
      final File script = File(
        '${Directory.systemTemp.createTempSync('nebula-test-').path}/s.sh',
      );
      await script.writeAsString(linuxVpnSupervisorScript);
      final ProcessResult result;
      try {
        result = await Process.run('bash', <String>['-n', script.path]);
      } on ProcessException {
        markTestSkipped('bash is not available');
        return;
      } finally {
        await script.parent.delete(recursive: true);
      }
      expect(result.exitCode, 0, reason: '${result.stderr}');
      // On Windows "bash" is WSL's, which cannot see a Windows temp path.
    },
    skip: Platform.isWindows ? 'checked on Linux' : null,
  );

  test('the helper starts with its shebang and undoes the routes it adds', () {
    expect(linuxVpnSupervisorScript, startsWith('#!/bin/bash'));
    expect(linuxVpnSupervisorScript, contains('trap cleanup EXIT'));
    expect(linuxVpnSupervisorScript, contains('rule del priority 9001'));
    // The kill switch goes with the session, and outlives a dead tunnel.
    expect(linuxVpnSupervisorScript, contains('table inet nebula_killswitch'));
    expect(
      linuxVpnSupervisorScript,
      contains('nft delete table inet nebula_killswitch'),
    );
    expect(linuxVpnSupervisorScript, contains('tunnel_lost'));
    // The DNS guard goes with the tunnel.
    expect(linuxVpnSupervisorScript, contains('table inet nebula_vpn'));
    expect(
      linuxVpnSupervisorScript,
      contains('nft delete table inet nebula_vpn'),
    );
    expect(linuxVpnSupervisorScript, contains('$linuxTunnelMark'));
    // The installed copy pins the packaged engine by these very paths.
    expect(linuxVpnSupervisorScript, contains(linuxInstalledHelper));
    expect(
      linuxVpnSupervisorScript,
      contains(
        '${linuxInstalledEngine.substring(0, linuxInstalledEngine.lastIndexOf('/'))}/\$engine_name',
      ),
    );
  });

  test('Hysteria2 on Linux: the nebula interface, routed by the helper', () {
    final String config = windowsHysteriaFullTunnelConfig(
      'server: vpn.example.org:443\nauth: x\n',
      '203.0.113.4',
      interfaceName: linuxTunnelInterface,
      platform: 'Linux',
      route: false,
    );
    // The helper reads the pinned server from this line to keep it out.
    expect(config, startsWith('server: 203.0.113.4:443\n'));
    expect(config, contains('name: $linuxTunnelInterface\n'));
    expect(config, isNot(contains('route:')));
    expect(
      () => windowsHysteriaFullTunnelConfig(
        'auth: x\n',
        '203.0.113.4',
        platform: 'Linux',
      ),
      throwsA(
        isA<StateError>().having(
          (StateError e) => e.message,
          'message',
          startsWith('Linux '),
        ),
      ),
    );
  });

  test('WireGuard DNS: addresses from every DNS line, names left out', () {
    expect(
      linuxWireGuardDns(
        '[Interface]\nPrivateKey = x=\nAddress = 10.8.0.2/32\n'
        'DNS = 1.1.1.1, 2606:4700:4700::1111, corp.example\n'
        'dns=9.9.9.9\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\n',
      ),
      <String>['1.1.1.1', '2606:4700:4700::1111', '9.9.9.9'],
    );
  });
}

List<Map<String, dynamic>> _maps(Object? list) =>
    (list! as List<dynamic>).cast<Map<String, dynamic>>();

Map<String, dynamic> _sockopt(Map<String, dynamic> outbound) =>
    (outbound['streamSettings'] as Map<String, dynamic>)['sockopt']
        as Map<String, dynamic>;
