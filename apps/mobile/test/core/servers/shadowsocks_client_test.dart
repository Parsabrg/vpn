import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';

/// A Shadowsocks-2022 credential as the API hands it out.
const Map<String, Object?> _ss = <String, Object?>{
  'client_id': 'c1',
  'uuid': '00000000-0000-4000-8000-000000000001',
  'server_address': 'vpn.example.test',
  'port': 8451,
  'sni': 'vpn.example.test',
  'transport': 'raw',
  'transport_security': 'none',
  'ad_block': false,
  'protocol': 'shadowsocks',
  'method': '2022-blake3-aes-128-gcm',
  'password': 'c2VydmVy:dXNlcg==',
};

class _Api implements HttpClientAdapter {
  _Api(this.body);

  final Map<String, Object?> body;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async => ResponseBody.fromString(
    jsonEncode(body),
    200,
    headers: <String, List<String>>{
      Headers.contentTypeHeader: <String>['application/json'],
    },
  );

  @override
  void close({bool force = false}) {}
}

Future<XrayClientResult> _request(Map<String, Object?> body) {
  final Dio dio = Dio(BaseOptions(baseUrl: 'https://api.example.test'))
    ..httpClientAdapter = _Api(body);
  return DioServerRepository(dio).requestXrayClient(
    deviceId: 'd',
    serverCode: 's',
    protocolProfileCode: 'shadowsocks-2022',
  );
}

void main() {
  test(
    'a Shadowsocks-2022 credential renders a Shadowsocks outbound',
    () async {
      final XrayClientResult client = await _request(_ss);

      expect(client.protocol, 'shadowsocks');
      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayClientConfigJson(
                  client,
                  localProxy: const LocalProxy(
                    port: 1,
                    username: 'u',
                    password: 'p',
                  ),
                ),
              )
              as Map<String, dynamic>;
      final Map<String, dynamic> proxy = (config['outbounds'] as List<dynamic>)
          .cast<Map<String, dynamic>>()
          .firstWhere((Map<String, dynamic> o) => o['tag'] == 'proxy');
      expect(proxy['protocol'], 'shadowsocks');
      final Map<String, dynamic> settings =
          proxy['settings'] as Map<String, dynamic>;
      final Map<String, dynamic> server =
          (settings['servers'] as List<dynamic>).single as Map<String, dynamic>;
      expect(server['address'], 'vpn.example.test');
      expect(server['port'], 8451);
      expect(server['method'], '2022-blake3-aes-128-gcm');
      expect(server['password'], 'c2VydmVy:dXNlcg==');
      // Its own encryption: no TLS for anyone to fingerprint.
      final Map<String, dynamic> stream =
          proxy['streamSettings'] as Map<String, dynamic>;
      expect(stream['security'], 'none');
      expect(stream.containsKey('tlsSettings'), isFalse);
    },
  );

  test('a server that sends no protocol means VLESS', () async {
    final XrayClientResult client = await _request(<String, Object?>{
      ..._ss,
      'protocol': null,
      'method': null,
      'password': null,
    });

    expect(client.protocol, 'vless');
    expect(client.password, isNull);
  });

  Map<String, dynamic> proxyOf(XrayClientResult client) {
    final Map<String, dynamic> config =
        jsonDecode(
              renderXrayClientConfigJson(
                client,
                localProxy: const LocalProxy(
                  port: 1,
                  username: 'u',
                  password: 'p',
                ),
              ),
            )
            as Map<String, dynamic>;
    return (config['outbounds'] as List<dynamic>)
        .cast<Map<String, dynamic>>()
        .firstWhere((Map<String, dynamic> o) => o['tag'] == 'proxy');
  }

  Map<String, dynamic> userOf(Map<String, dynamic> proxy) {
    final Map<String, dynamic> settings =
        proxy['settings'] as Map<String, dynamic>;
    final Map<String, dynamic> server =
        (settings['vnext'] as List<dynamic>).single as Map<String, dynamic>;
    return (server['users'] as List<dynamic>).single as Map<String, dynamic>;
  }

  test('a VMess WebSocket credential renders VMess with no TLS', () async {
    final XrayClientResult client = await _request(<String, Object?>{
      ..._ss,
      'port': 8455,
      'transport': 'websocket',
      'path': '/vw',
      'protocol': 'vmess',
      'method': null,
      'password': null,
    });
    final Map<String, dynamic> proxy = proxyOf(client);

    expect(proxy['protocol'], 'vmess');
    expect(userOf(proxy), <String, dynamic>{
      'id': '00000000-0000-4000-8000-000000000001',
      'security': 'auto',
    });
    final Map<String, dynamic> stream =
        proxy['streamSettings'] as Map<String, dynamic>;
    expect(stream['network'], 'websocket');
    expect(stream['security'], 'none');
    expect((stream['wsSettings'] as Map<String, dynamic>)['path'], '/vw');
  });

  test('a VLESS Encryption credential dials with its client string', () async {
    final XrayClientResult client = await _request(<String, Object?>{
      ..._ss,
      'port': 8453,
      'protocol': 'vless',
      'method': null,
      'password': null,
      'encryption': 'mlkem768x25519plus.native.0rtt.k',
    });
    final Map<String, dynamic> proxy = proxyOf(client);

    expect(proxy['protocol'], 'vless');
    expect(userOf(proxy)['encryption'], 'mlkem768x25519plus.native.0rtt.k');
    // No mux: its UDP lost DNS answers over VLESS Encryption.
    expect(proxy.containsKey('mux'), isFalse);
    // Plain VLESS keeps it.
    final XrayClientResult plain = await _request(<String, Object?>{
      ..._ss,
      'protocol': 'vless',
      'method': null,
      'password': null,
    });
    expect(proxyOf(plain).containsKey('mux'), isTrue);
  });
}
