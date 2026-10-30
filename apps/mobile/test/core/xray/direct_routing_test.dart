import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/advanced_settings_store.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';

const LocalProxy _proxy = LocalProxy(port: 10902, username: 'u', password: 'p');

XrayClientResult _client({String transport = 'xhttp'}) => XrayClientResult(
  clientId: 'c',
  uuid: '6f1c2a7e-3b9d-4c55-9a0e-2d1f00e2e2e2',
  serverAddress: 'vpn.example.org',
  port: 443,
  sni: 'vpn.example.org',
  transport: transport,
  transportSecurity: 'tls',
  adBlock: true,
  path: '/x',
);

Map<String, dynamic> _render(
  AdvancedSettings settings, {
  String transport = 'xhttp',
}) =>
    jsonDecode(
          renderXrayClientConfigJson(
            _client(transport: transport),
            localProxy: _proxy,
            settings: settings,
          ),
        )
        as Map<String, dynamic>;

List<Map<String, dynamic>> _rules(Map<String, dynamic> config) =>
    ((config['routing'] as Map<String, dynamic>)['rules'] as List<dynamic>)
        .cast<Map<String, dynamic>>();

Iterable<Object?> _tags(Map<String, dynamic> config) =>
    (config['outbounds'] as List<dynamic>).cast<Map<String, dynamic>>().map(
      (Map<String, dynamic> o) => o['tag'],
    );

bool? _sniffingEnabled(Map<String, dynamic> config) =>
    ((config['inbounds'] as List<dynamic>).first
            as Map<String, dynamic>)['sniffing']
        is Map<String, dynamic>
    ? (((config['inbounds'] as List<dynamic>).first
                  as Map<String, dynamic>)['sniffing']
              as Map<String, dynamic>)['enabled']
          as bool?
    : null;

void main() {
  group('a website as a bypass rule names it', () {
    test('keeps the host, lower-case, without www, scheme or path', () {
      expect(normalizeBypassDomain('Bank.Example'), 'bank.example');
      expect(
        normalizeBypassDomain('https://www.Bank.example:8443/login?x=1'),
        'bank.example',
      );
      expect(normalizeBypassDomain('*.shop.example.'), 'shop.example');
      expect(
        normalizeBypassDomain('  mail.service.co.uk '),
        'mail.service.co.uk',
      );
    });

    test('refuses what is not a host name', () {
      for (final String bad in <String>[
        '',
        'localhost',
        'not a site',
        '1.2.3.4',
        'bad_name.example',
        '-x.example',
      ]) {
        expect(normalizeBypassDomain(bad), isNull, reason: bad);
      }
    });
  });

  test('by default nothing leaves directly', () {
    final Map<String, dynamic> config = _render(AdvancedSettings.defaults);
    expect(_tags(config), isNot(contains('direct')));
  });

  test('Iranian sites: .ir, category-ir and geoip:ir go direct', () {
    final Map<String, dynamic> config = _render(
      AdvancedSettings.defaults.copyWith(iranDirect: true),
    );
    final Map<String, dynamic> routing =
        config['routing'] as Map<String, dynamic>;
    // An address rule needs an address: names no rule matches are looked up.
    expect(routing['domainStrategy'], 'IPIfNonMatch');
    final List<Map<String, dynamic>> rules = _rules(config);
    // The ad block still comes first.
    expect(rules.first['outboundTag'], 'ad-block');
    expect(rules[1], <String, dynamic>{
      'type': 'field',
      'outboundTag': 'direct',
      'domain': <String>['domain:ir', 'geosite:category-ir'],
    });
    expect(rules[2], <String, dynamic>{
      'type': 'field',
      'outboundTag': 'direct',
      'ip': <String>['geoip:ir'],
    });
    expect(_tags(config), contains('direct'));
    expect(_sniffingEnabled(config), isTrue);
  });

  test('websites that skip the VPN go direct, after the ad block', () {
    final List<Map<String, dynamic>> rules = _rules(
      _render(
        AdvancedSettings.defaults.copyWith(
          bypassDomains: <String>['bank.example', 'shop.example'],
        ),
      ),
    );
    expect(rules.first['outboundTag'], 'ad-block');
    expect(rules[1], <String, dynamic>{
      'type': 'field',
      'outboundTag': 'direct',
      'domain': <String>['domain:bank.example', 'domain:shop.example'],
    });
  });

  test('addresses and ranges skip the VPN by an ip rule beside the names', () {
    // Roadmap 21: routing by IP/CIDR as well as by domain.
    final List<Map<String, dynamic>> rules = _rules(
      _render(
        AdvancedSettings.defaults.copyWith(
          bypassDomains: <String>[
            'bank.example',
            '203.0.113.7',
            '198.51.100.0/24',
            '2001:db8::/32',
          ],
        ),
      ),
    );
    expect(rules[1], <String, dynamic>{
      'type': 'field',
      'outboundTag': 'direct',
      'domain': <String>['domain:bank.example'],
    });
    expect(rules[2], <String, dynamic>{
      'type': 'field',
      'outboundTag': 'direct',
      'ip': <String>['203.0.113.7', '198.51.100.0/24', '2001:db8::/32'],
    });
  });

  test('an entry is a website or an address or range, nothing else', () {
    expect(normalizeBypassEntry(' 203.0.113.7 '), '203.0.113.7');
    expect(normalizeBypassEntry('198.51.100.0/24'), '198.51.100.0/24');
    expect(normalizeBypassEntry('2001:DB8::/32'), '2001:db8::/32');
    expect(normalizeBypassEntry('https://www.Bank.example/x'), 'bank.example');
    for (final String bad in <String>[
      '0.0.0.0/0',
      '::/0',
      '203.0.113.0/33',
      '203.0.113.0/x',
      '1.2.3.4/8/9',
      'not a site',
    ]) {
      expect(normalizeBypassEntry(bad), isNull, reason: bad);
    }
  });

  test('Hysteria2 has no routing, so it keeps everything in the tunnel', () {
    final AdvancedSettings settings = AdvancedSettings.defaults.copyWith(
      iranDirect: true,
      bypassDomains: <String>['bank.example'],
    );
    expect(
      routesAnythingDirect(_client(transport: 'hysteria'), settings),
      isFalse,
    );
    expect(routesIranDirect(_client(transport: 'hysteria'), settings), isFalse);
  });

  group("the app's own API goes through the server", () {
    Map<String, dynamic> render(AdvancedSettings settings) =>
        jsonDecode(
              renderXrayClientConfigJson(
                _client(),
                localProxy: _proxy,
                settings: settings,
                apiHosts: const <String>[
                  'cdn.example.org',
                  'front.example.app',
                ],
              ),
            )
            as Map<String, dynamic>;

    test('ahead of every direct rule, in sanctions-only mode', () {
      final List<Map<String, dynamic>> rules = _rules(
        render(
          AdvancedSettings.defaults.copyWith(
            routingMode: RoutingMode.sanctionedOnly,
            bypassDomains: const <String>['example.org'],
          ),
        ),
      );
      expect(rules.first['outboundTag'], 'proxy');
      expect(rules.first['domain'], <String>[
        'full:cdn.example.org',
        'full:front.example.app',
      ]);
    });

    test('no rule when nothing leaves directly', () {
      final List<Map<String, dynamic>> rules = _rules(
        render(AdvancedSettings.defaults),
      );
      expect(
        rules.where((Map<String, dynamic> r) => r['outboundTag'] == 'proxy'),
        isEmpty,
      );
    });
  });
}
