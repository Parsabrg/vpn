import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';

const LocalProxy _proxy = LocalProxy(port: 10902, username: 'u', password: 'p');

XrayClientResult _client({
  String transport = 'websocket',
  String host = 'cdn.example.org',
  String? ech = 'cloudflare-ech.com+https://dns.example/dns-query',
}) => XrayClientResult(
  clientId: 'c',
  uuid: '6f1c2a7e-3b9d-4c55-9a0e-2d1f00e2e2e2',
  serverAddress: host,
  port: 443,
  sni: host,
  transport: transport,
  transportSecurity: 'tls',
  adBlock: false,
  path: '/ws',
  echConfigList: ech,
);

Map<String, dynamic> _render(XrayClientResult r, CdnDial dial) =>
    jsonDecode(renderXrayClientConfigJson(r, localProxy: _proxy, cdnDial: dial))
        as Map<String, dynamic>;

Map<String, dynamic> _proxyStream(Map<String, dynamic> c) =>
    ((c['outbounds'] as List<dynamic>).first
            as Map<String, dynamic>)['streamSettings']
        as Map<String, dynamic>;

Map<String, dynamic> _tls(Map<String, dynamic> c) =>
    _proxyStream(c)['tlsSettings'] as Map<String, dynamic>;

Map<String, dynamic> _hosts(Map<String, dynamic> c) =>
    ((c['dns'] as Map<String, dynamic>)['hosts'] as Map<String, dynamic>?) ??
    <String, dynamic>{};

void main() {
  test('the dial that worked last is tried first; IPv6 only with IPv6', () {
    expect(cdnDialOrder(hasIpv6: false), <CdnDial>[
      CdnDial.asGiven,
      CdnDial.plain,
      CdnDial.ff,
    ]);
    expect(cdnDialOrder(lastWorked: CdnDial.ff, hasIpv6: true), <CdnDial>[
      CdnDial.ff,
      CdnDial.asGiven,
      CdnDial.plain,
      CdnDial.ipv6,
    ]);
  });

  test('as given keeps ECH and the route as it is', () {
    final Map<String, dynamic> c = _render(_client(), CdnDial.asGiven);
    expect(_tls(c)['echConfigList'], isNotNull);
    expect(_hosts(c), isEmpty);
  });

  test(
    'F&F: no ECH, split hello, unsafe + semi-python, WebSocket ALPN, clean address',
    () {
      final Map<String, dynamic> c = _render(_client(), CdnDial.ff);
      final Map<String, dynamic> tls = _tls(c);
      expect(tls.containsKey('echConfigList'), isFalse);
      expect(tls['fingerprint'], 'unsafe');
      expect(tls['cipherSuites'], kSemiPythonCipherSuites);
      expect(tls['alpn'], <String>['http/1.1']);
      expect(tls['serverName'], 'cdn.example.org');
      final List<dynamic> tcp =
          (_proxyStream(c)['finalmask'] as Map<String, dynamic>)['tcp']
              as List<dynamic>;
      expect(
        ((tcp.first as Map<String, dynamic>)['settings']
            as Map<String, dynamic>)['lengths'],
        <String>['0', '104', '1'],
      );
      expect(_hosts(c)['cdn.example.org'], kFfCleanIp);
      expect(
        _proxyStream(c)['sockopt'],
        containsPair('domainStrategy', 'UseIPv4'),
      );
    },
  );

  test('plain: Chrome, the transport ALPN, no ECH, no split', () {
    final Map<String, dynamic> c = _render(
      _client(transport: 'xhttp'),
      CdnDial.plain,
    );
    expect(_tls(c)['fingerprint'], 'chrome');
    expect(_tls(c)['alpn'], <String>['h2', 'http/1.1']);
    expect(_tls(c).containsKey('echConfigList'), isFalse);
    expect(_proxyStream(c).containsKey('finalmask'), isFalse);
  });

  test('IPv6: Cloudflare IPv6 edge, dialled as IPv6, gRPC ALPN', () {
    final Map<String, dynamic> c = _render(
      _client(transport: 'grpc'),
      CdnDial.ipv6,
    );
    expect(_hosts(c)['cdn.example.org'], kCloudflareIpv6);
    expect(
      _proxyStream(c)['sockopt'],
      containsPair('domainStrategy', 'UseIPv6'),
    );
    expect(_tls(c)['alpn'], <String>['h2']);
  });

  test('a web-host front (no ECH key) is never redialled', () {
    final XrayClientResult front = _client(
      transport: 'xhttp',
      host: 'front.example.app',
      ech: null,
    );
    expect(isCloudflareRoute(front), isFalse);
    final Map<String, dynamic> c = _render(front, CdnDial.ff);
    expect(_tls(c)['fingerprint'], 'chrome');
    expect(_hosts(c), isEmpty);
  });
}
