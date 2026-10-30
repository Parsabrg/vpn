import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/profile_link.dart';
import 'package:nebula_mobile/core/storage/advanced_settings_store.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';

const String _id = '0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b';

void main() {
  test('a Worker link through a clean address reads as a profile', () {
    // The shape a Cloudflare Worker panel hands out: the address is an edge
    // address, the Worker is named by sni and host.
    final ImportedProfile? profile = parseVlessLink(
      '  vless://$_id@188.114.97.6:443?encryption=none&security=tls'
      '&sni=app.example.workers.dev&fp=randomized&alpn=http%2F1.1&type=ws'
      '&host=app.example.workers.dev&path=%2Fabc%3Fed%3D2560#My%20Worker \n',
    );
    expect(profile, isNotNull);
    expect(profile!.name, 'My Worker');
    expect(profile.client.uuid, _id);
    expect(profile.client.serverAddress, '188.114.97.6');
    expect(profile.client.port, 443);
    expect(profile.client.sni, 'app.example.workers.dev');
    expect(profile.client.transport, 'websocket');
    expect(profile.client.transportSecurity, 'tls');
    expect(profile.client.path, '/abc?ed=2560');
  });

  test('what is left out takes the usual value', () {
    final ImportedProfile profile = parseVlessLink(
      'VLESS://${_id.toUpperCase()}@edge.example.com?security=tls&type=xhttp',
    )!;
    expect(profile.name, 'edge.example.com');
    expect(profile.client.uuid, _id);
    expect(profile.client.port, 443);
    expect(profile.client.sni, 'edge.example.com');
    expect(profile.client.transport, 'xhttp');
    expect(profile.client.path, '/');
  });

  test('a gRPC link carries its service name, not a path', () {
    final ImportedProfile profile = parseVlessLink(
      'vless://$_id@edge.example.com:2053?security=tls&type=grpc'
      '&serviceName=tunnel&sni=edge.example.com',
    )!;
    expect(profile.client.transport, 'grpc');
    expect(profile.client.serviceName, 'tunnel');
    expect(profile.client.path, isNull);
    expect(profile.client.port, 2053);
  });

  test('the config written from a link dials what the link said', () {
    final ImportedProfile profile = parseVlessLink(
      'vless://$_id@188.114.97.6:8443?security=tls&type=ws'
      '&sni=app.example.workers.dev&path=%2Fws',
    )!;
    final Map<String, dynamic> config =
        jsonDecode(
              renderXrayClientConfigJson(
                profile.client,
                localProxy: const LocalProxy(
                  port: 20443,
                  username: 'n0011223344556677',
                  password: '00112233445566778899aabbccddeeff',
                ),
              ),
            )
            as Map<String, dynamic>;
    final Map<String, dynamic> outbound = (config['outbounds'] as List<dynamic>)
        .cast<Map<String, dynamic>>()
        .firstWhere((Map<String, dynamic> o) => o['tag'] == 'proxy');
    final Map<String, dynamic> server =
        ((outbound['settings'] as Map<String, dynamic>)['vnext']
                    as List<dynamic>)
                .first
            as Map<String, dynamic>;
    final Map<String, dynamic> stream =
        outbound['streamSettings'] as Map<String, dynamic>;
    expect(server['address'], '188.114.97.6');
    expect(server['port'], 8443);
    expect(stream['network'], 'websocket');
    expect((stream['wsSettings'] as Map<String, dynamic>)['path'], '/ws');
    expect(
      (stream['tlsSettings'] as Map<String, dynamic>)['serverName'],
      'app.example.workers.dev',
    );
  });

  group('refused rather than approximated', () {
    const String base = 'vless://$_id@edge.example.com:443';
    final Map<String, String> links = <String, String>{
      'not a link': 'hello',
      'another protocol':
          'trojan://secret@edge.example.com:443?security=tls&type=ws',
      'no TLS': '$base?security=none&type=ws',
      'TLS not stated': '$base?type=ws',
      'REALITY on anything but raw TCP':
          '$base?security=reality&type=xhttp&pbk=abc&sni=www.example.com',
      'REALITY with no key': '$base?security=reality&sni=www.example.com',
      'REALITY with no name': '$base?security=reality&pbk=abc',
      'certificate checks off': '$base?security=tls&type=ws&allowInsecure=1',
      'an XTLS flow': '$base?security=tls&type=ws&flow=xtls-rprx-vision',
      'an encryption this app does not speak':
          '$base?security=tls&type=ws&encryption=mlkem768x25519plus',
      'a Host that is not the TLS name':
          '$base?security=tls&type=ws&sni=a.example.com&host=b.example.com',
      'not a UUID':
          'vless://password@edge.example.com:443?security=tls&type=ws',
      'no address': 'vless://$_id@:443?security=tls&type=ws',
      'port zero': 'vless://$_id@edge.example.com:0?security=tls&type=ws',
    };
    for (final MapEntry<String, String> link in links.entries) {
      test(link.key, () => expect(parseVlessLink(link.value), isNull));
    }
  });

  group('other protocols', () {
    Map<String, dynamic> outbound(ImportedProfile profile) {
      final Map<String, dynamic> config =
          jsonDecode(renderXrayDelayProbeConfigJson(profile.client))
              as Map<String, dynamic>;
      return (config['outbounds'] as List<dynamic>).first
          as Map<String, dynamic>;
    }

    test('VLESS REALITY with Vision', () {
      final ImportedProfile profile = parseLink(
        'vless://$_id@203.0.113.10:443?security=reality&type=tcp'
        '&flow=xtls-rprx-vision&sni=www.speedtest.net&fp=chrome'
        '&pbk=sP-3pewJA6ngGyEzunuBw6yLYPLbt00A2dDmVdMP1ks&sid=613165694276f61b'
        '#Reality-443',
      )!;
      expect(profile.name, 'Reality-443');
      final Map<String, dynamic> out = outbound(profile);
      final Map<String, dynamic> stream =
          out['streamSettings'] as Map<String, dynamic>;
      expect(stream['security'], 'reality');
      expect(stream['network'], 'raw');
      final Map<String, dynamic> reality =
          stream['realitySettings'] as Map<String, dynamic>;
      expect(reality['serverName'], 'www.speedtest.net');
      expect(
        reality['publicKey'],
        'sP-3pewJA6ngGyEzunuBw6yLYPLbt00A2dDmVdMP1ks',
      );
      expect(reality['shortId'], '613165694276f61b');
      expect(jsonEncode(out), contains('xtls-rprx-vision'));
      // No TLS settings of its own: REALITY proves the server by its key.
      expect(stream.containsKey('tlsSettings'), isFalse);
    });

    test('Vision is never wrapped in Mux', () {
      final ImportedProfile profile = parseLink(
        'vless://$_id@example.com:443?security=tls&type=tcp'
        '&flow=xtls-rprx-vision&sni=example.com',
      )!;
      final Map<String, dynamic> config =
          jsonDecode(
                renderXrayDelayProbeConfigJson(
                  profile.client,
                  settings: AdvancedSettings.defaults.copyWith(
                    muxEnabled: true,
                  ),
                ),
              )
              as Map<String, dynamic>;
      final Map<String, dynamic> out =
          (config['outbounds'] as List<dynamic>).first as Map<String, dynamic>;
      expect(out.containsKey('mux'), isFalse);
    });

    test('Trojan over WebSocket keeps TLS and the certificate check', () {
      final ImportedProfile profile = parseLink(
        'trojan://s3cret%40pw@cdn.example.com:443?type=ws&path=%2Ft'
        '&sni=cdn.example.com#My%20Trojan',
      )!;
      final Map<String, dynamic> out = outbound(profile);
      expect(out['protocol'], 'trojan');
      final Map<String, dynamic> server =
          ((out['settings'] as Map<String, dynamic>)['servers']
                      as List<dynamic>)
                  .first
              as Map<String, dynamic>;
      expect(server['password'], 's3cret@pw');
      final Map<String, dynamic> stream =
          out['streamSettings'] as Map<String, dynamic>;
      expect(stream['security'], 'tls');
      expect((stream['wsSettings'] as Map<String, dynamic>)['path'], '/t');
      expect(jsonEncode(stream), isNot(contains('allowInsecure')));
    });

    test('Shadowsocks in each form', () {
      final String encoded = base64Url
          .encode(utf8.encode('chacha20-ietf-poly1305:pw-123'))
          .replaceAll('=', '');
      final String old = base64.encode(
        utf8.encode('aes-256-gcm:pw-123@ss.example.com:8388'),
      );
      for (final String link in <String>[
        'ss://$encoded@ss.example.com:8388#SIP002',
        'ss://aes-256-gcm:pw-123@ss.example.com:8388#Plain',
        'ss://$old#Old',
      ]) {
        final ImportedProfile? profile = parseLink(link);
        expect(profile, isNotNull, reason: link);
        final Map<String, dynamic> server =
            (((outbound(profile!)['settings']
                            as Map<String, dynamic>)['servers'])
                        as List<dynamic>)
                    .first
                as Map<String, dynamic>;
        expect(server['password'], 'pw-123', reason: link);
        expect(<String>[
          'chacha20-poly1305',
          'aes-256-gcm',
        ], contains(server['method']));
        expect(server['port'], 8388);
      }
    });

    test('Hysteria2 with Salamander', () {
      final ImportedProfile profile = parseLink(
        'hysteria2://auth-1@hy.example.com:8443/?sni=hy.example.com'
        '&obfs=salamander&obfs-password=salt#Hy',
      )!;
      expect(profile.client.transport, 'hysteria');
      expect(profile.client.uuid, 'auth-1');
      expect(profile.client.obfsPassword, 'salt');
    });

    final Map<String, String> refused = <String, String>{
      'Trojan with certificate checks off':
          'trojan://pw@example.com:443?type=ws&allowInsecure=1',
      'Trojan without TLS': 'trojan://pw@example.com:443?security=none',
      'Shadowsocks through a plugin':
          'ss://aes-256-gcm:pw@example.com:8388?plugin=v2ray-plugin',
      'Shadowsocks with a stream cipher':
          'ss://aes-256-cfb:pw@example.com:8388',
      'Hysteria2 with certificate checks off':
          'hysteria2://a@example.com:443/?insecure=1',
      'Hysteria2 port hopping': 'hysteria2://a@example.com:443/?mport=443-500',
      'Hysteria2 with an unknown obfuscation':
          'hysteria2://a@example.com:443/?obfs=gost&obfs-password=x',
      'VMess, which this app does not speak': 'vmess://eyJhZGQiOiJ4In0=',
    };
    for (final MapEntry<String, String> link in refused.entries) {
      test('refused: ${link.key}', () => expect(parseLink(link.value), isNull));
    }
  });

  test('a link keeps its Encrypted Client Hello setting', () {
    // v2rayN's own subscription line; without ECH, Cloudflare carried
    // nothing from Iran.
    final ImportedProfile? profile = parseLink(
      'vless://11111111-1111-4111-8111-111111111111@relay.example.org:2053'
      '?path=%2Fapi%2Fv1%2Fupdate&security=tls&encryption=none&insecure=0'
      '&host=relay.example.org&type=ws&allowInsecure=0&sni=relay.example.org'
      '&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1#WS-CF-auto',
    );
    expect(profile?.client.echConfigList, 'cloudflare-ech.com+udp://1.1.1.1');
    expect(
      parseLink(
        'vless://$_id@h.example.org:443?security=tls&type=ws&sni=h.example.org',
      )?.client.echConfigList,
      isNull,
    );
  });
}
