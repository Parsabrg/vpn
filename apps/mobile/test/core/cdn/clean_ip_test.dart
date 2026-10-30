import 'dart:convert';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/cdn/clean_ip.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/advanced_settings_store.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/windows_tunnel_config.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';

XrayClientResult _client(String transport) => XrayClientResult(
  clientId: 'c',
  uuid: '6f1c2a7e-3b9d-4c55-9a0e-2d1f00e2e2e2',
  serverAddress: 'cdn.example.org',
  port: 443,
  sni: 'cdn.example.org',
  transport: transport,
  transportSecurity: 'tls',
  adBlock: false,
  path: '/x',
);

Map<String, dynamic> _render(String transport, AdvancedSettings settings) =>
    jsonDecode(
          renderXrayClientConfigJson(
            _client(transport),
            localProxy: const LocalProxy(port: 1, username: 'u', password: 'p'),
            settings: settings,
          ),
        )
        as Map<String, dynamic>;

void main() {
  test('Cloudflare addresses are recognised; others are not', () {
    expect(isCloudflareAddress('104.16.1.1'), isTrue);
    expect(isCloudflareAddress('172.67.10.10'), isTrue);
    expect(isCloudflareAddress('188.114.97.3'), isTrue);
    expect(isCloudflareAddress('8.8.8.8'), isFalse);
    expect(isCloudflareAddress('192.168.1.1'), isFalse);
    expect(isCloudflareAddress('not an address'), isFalse);
  });

  test('a sample is distinct, inside the ranges, and avoids .0 and .255', () {
    final List<String> sample = sampleCloudflareAddresses(
      200,
      random: Random(7),
    );
    expect(sample.toSet(), hasLength(200));
    for (final String ip in sample) {
      expect(isCloudflareAddress(ip), isTrue, reason: ip);
      expect(ip.endsWith('.0') || ip.endsWith('.255'), isFalse, reason: ip);
    }
  });

  test('a scan keeps the addresses that answered, fastest first', () async {
    final Map<String, int?> answers = <String, int?>{
      '104.16.0.1': 300,
      '104.16.0.2': null,
      '104.16.0.3': 120,
      '104.16.0.4': 220,
    };
    int progress = 0;
    final List<CleanIpResult> found = await scanCleanIps(
      'cdn.example.org',
      answers.keys.toList(),
      concurrency: 2,
      probe: (String ip, String host) async => answers[ip],
      onProgress: (int done) => progress = done,
    );
    expect(found.map((CleanIpResult r) => r.ip), <String>[
      '104.16.0.3',
      '104.16.0.4',
      '104.16.0.1',
    ]);
    expect(progress, 4);
  });

  group('the chosen address', () {
    final AdvancedSettings chosen = AdvancedSettings.defaults.copyWith(
      cleanIp: () => '104.16.0.3',
      cleanIpHost: () => 'cdn.example.org',
    );

    test('pins the CDN route to it, keeping the name for TLS', () {
      final Map<String, dynamic> config = _render('xhttp', chosen);
      expect(pinnedUpstream(config, 'cdn.example.org'), '104.16.0.3');
    });

    test('leaves another route, and transports without a CDN, alone', () {
      expect(pinnedUpstream(_render('raw', chosen), 'cdn.example.org'), isNull);
      expect(
        pinnedUpstream(
          _render(
            'xhttp',
            chosen.copyWith(cleanIpHost: () => 'other.example.org'),
          ),
          'cdn.example.org',
        ),
        isNull,
      );
      expect(
        pinnedUpstream(
          _render('xhttp', AdvancedSettings.defaults),
          'cdn.example.org',
        ),
        isNull,
      );
    });
  });
}
