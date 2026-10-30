import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/profile_link.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';

const LocalProxy _proxy = LocalProxy(
  port: 20443,
  username: 'n0011223344556677',
  password: '00112233445566778899aabbccddeeff',
);

Map<String, dynamic> _tlsFor(XrayClientResult client) {
  final Map<String, dynamic> config =
      jsonDecode(renderXrayClientConfigJson(client, localProxy: _proxy))
          as Map<String, dynamic>;
  final Map<String, dynamic> outbound = (config['outbounds'] as List<dynamic>)
      .cast<Map<String, dynamic>>()
      .firstWhere((Map<String, dynamic> o) => o['tag'] == 'proxy');
  return (outbound['streamSettings'] as Map<String, dynamic>)['tlsSettings']
      as Map<String, dynamic>;
}

XrayClientResult _link(String sni) => parseVlessLink(
  'vless://0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b@$sni:443'
  '?security=tls&type=ws&sni=$sni&path=%2F',
)!.client;

XrayClientResult _fromServer({String? ech}) => XrayClientResult(
  clientId: 'c',
  uuid: '0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b',
  serverAddress: 'cdn.example.org',
  port: 443,
  sni: 'cdn.example.org',
  transport: 'xhttp',
  transportSecurity: 'tls',
  adBlock: false,
  path: '/xhttp',
  echConfigList: ech,
);

void main() {
  test('a free relay on workers.dev is reached with ECH', () {
    expect(
      _tlsFor(_link('App.Example.Workers.dev'))['echConfigList'],
      kCloudflareEch,
    );
  });

  test('the CDN route uses the ECH the server hands out', () {
    expect(
      _tlsFor(
        _fromServer(ech: 'cloudflare-ech.com+udp://1.1.1.1'),
      )['echConfigList'],
      'cloudflare-ech.com+udp://1.1.1.1',
    );
  });

  test('anything else is dialled as it always was', () {
    expect(_tlsFor(_fromServer()).containsKey('echConfigList'), isFalse);
    expect(
      _tlsFor(_link('workers.dev.example.org')).containsKey('echConfigList'),
      isFalse,
    );
  });
}
