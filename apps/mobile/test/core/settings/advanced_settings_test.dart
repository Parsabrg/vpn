/// The core-level settings, and what they do to the generated config.
///
/// The load-bearing test here is the first one: with nothing turned on, the
/// config must come out byte for byte as it did before any of this existed.
/// People on these networks cannot tell an app update apart from a change in
/// what is being blocked, so a setting that quietly alters a working tunnel
/// costs them a day of guessing which it was.
library;

import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/settings/advanced_settings_controller.dart';
import 'package:nebula_mobile/core/storage/advanced_settings_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';
import 'package:nebula_mobile/core/xray/xray_config.dart';
import 'package:shared_preferences/shared_preferences.dart';

XrayClientResult _client({bool adBlock = false}) {
  return XrayClientResult(
    clientId: 'client-1',
    uuid: '11111111-1111-1111-1111-111111111111',
    serverAddress: 'vpn.example.org',
    port: 8445,
    sni: 'vpn.example.org',
    transport: 'xhttp',
    transportSecurity: 'tls',
    adBlock: adBlock,
    path: '/xhttp',
  );
}

Map<String, dynamic> _config(
  XrayClientResult client, {
  AdvancedSettings settings = AdvancedSettings.defaults,
}) {
  return jsonDecode(
        renderXrayClientConfigJson(
          client,
          settings: settings,
          localProxy: _localProxy,
        ),
      )
      as Map<String, dynamic>;
}

/// Typed accessors, so the assertions below read the config rather than
/// walking it through `dynamic` and losing every type check on the way.
Map<String, dynamic> _section(Map<String, dynamic> config, String key) =>
    config[key] as Map<String, dynamic>;

List<Map<String, dynamic>> _list(Map<String, dynamic> config, String key) =>
    (config[key] as List<dynamic>).cast<Map<String, dynamic>>();

Map<String, dynamic> _outbound(Map<String, dynamic> config) =>
    _list(config, 'outbounds').first;

Map<String, dynamic> _inbound(Map<String, dynamic> config) =>
    _list(config, 'inbounds').first;

List<String> _dnsServers(Map<String, dynamic> config) =>
    (_section(config, 'dns')['servers'] as List<dynamic>).cast<String>();

ProviderContainer _container([AdvancedSettingsStore? store]) {
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      advancedSettingsStoreProvider.overrideWithValue(
        store ?? InMemoryAdvancedSettingsStore(),
      ),
    ],
  );
  addTearDown(container.dispose);
  return container;
}

const LocalProxy _localProxy = LocalProxy(
  port: 20443,
  username: 'n0011223344556677',
  password: '00112233445566778899aabbccddeeff',
);

void main() {
  group('local proxy settings', () {
    test('mode and port survive a restart', () async {
      SharedPreferences.setMockInitialValues(<String, Object>{});
      final SharedPreferences preferences =
          await SharedPreferences.getInstance();
      final SharedPreferencesAdvancedSettingsStore store =
          SharedPreferencesAdvancedSettingsStore(preferences);

      await store.write(
        AdvancedSettings.defaults.copyWith(
          connectionMode: ConnectionMode.localProxy,
          localProxyPort: 20820,
        ),
      );

      final AdvancedSettings read = store.read();
      expect(read.connectionMode, ConnectionMode.localProxy);
      expect(read.localProxyPort, 20820);
    });

    test('a stored port no app could use reads as the default', () async {
      SharedPreferences.setMockInitialValues(<String, Object>{
        'nebula.local_proxy_port': 80,
      });
      final SharedPreferences preferences =
          await SharedPreferences.getInstance();

      expect(
        SharedPreferencesAdvancedSettingsStore(
          preferences,
        ).read().localProxyPort,
        AdvancedSettings.defaultLocalProxyPort,
      );
    });

    test('the default port is not one v2rayNG uses', () {
      expect(AdvancedSettings.defaultLocalProxyPort, isNot(10808));
      expect(AdvancedSettings.defaultLocalProxyPort, isNot(10809));
    });

    test('only ports an app can be pointed at are valid', () {
      expect(isValidLocalProxyPort(1023), isFalse);
      expect(isValidLocalProxyPort(1024), isTrue);
      expect(isValidLocalProxyPort(65535), isTrue);
      expect(isValidLocalProxyPort(65536), isFalse);
    });
  });

  group('doing nothing changes nothing', () {
    test('the default config is identical to the one with no settings', () {
      // The rule this whole feature is built around.
      for (final bool adBlock in <bool>[false, true]) {
        expect(
          renderXrayClientConfigJson(
            _client(adBlock: adBlock),
            localProxy: _localProxy,
          ),
          renderXrayClientConfigJson(
            _client(adBlock: adBlock),
            settings: AdvancedSettings.defaults,
            localProxy: _localProxy,
          ),
        );
      }
    });

    test('off, TCP is not muxed but UDP shares one connection', () {
      // Every app's DNS over one connection instead of a new one each, and
      // QUIC refused so apps use TCP; TCP itself stays one connection each.
      final Map<String, dynamic> mux = _section(
        _outbound(_config(_client())),
        'mux',
      );
      expect(mux['enabled'], isTrue);
      expect(mux['concurrency'], -1);
      expect(mux['xudpConcurrency'], 16);
      expect(mux['xudpProxyUDP443'], 'reject');
    });

    test('the shipped resolvers still depend on the profile', () {
      expect(_dnsServers(_config(_client())), <String>['94.140.14.140']);
      expect(_dnsServers(_config(_client(adBlock: true))), <String>[
        '94.140.14.14',
      ]);
    });

    test('sniffing still follows the profile', () {
      // On where there are rules to feed, off where there are none, which is
      // what the app has always done.
      expect(_inbound(_config(_client())), isNot(contains('sniffing')));
      expect(
        _section(
          _inbound(_config(_client(adBlock: true))),
          'sniffing',
        )['enabled'],
        isTrue,
      );
    });

    test('the log level is the one the core was already given', () {
      expect(_section(_config(_client()), 'log')['loglevel'], 'warning');
    });
  });

  group('DNS', () {
    test('a chosen resolver overrides the profile on both kinds', () {
      // Somebody who typed an address in did so to override exactly this,
      // including on an ad-block profile.
      const AdvancedSettings settings = AdvancedSettings.defaults;
      final AdvancedSettings chosen = settings.copyWith(
        dnsServers: <String>['9.9.9.9'],
      );

      expect(_dnsServers(_config(_client(), settings: chosen)), <String>[
        '9.9.9.9',
      ]);
      expect(
        _dnsServers(_config(_client(adBlock: true), settings: chosen)),
        <String>['9.9.9.9'],
      );
    });

    test('an IPv6 resolver never reaches the tunnel', () {
      // The plugin turns this list into the tunnel's DNS servers, and Android
      // reads the families in it as the families this VPN handles: one IPv6
      // entry made it route the whole of ::/0 into a tunnel that carries no
      // IPv6, where the queries were dropped. Measured on a phone -- only the
      // v4 resolver ever validated.
      final AdvancedSettings mixed = AdvancedSettings.defaults.copyWith(
        dnsServers: <String>['2606:4700:4700::1111', '9.9.9.9'],
      );

      expect(_dnsServers(_config(_client(), settings: mixed)), <String>[
        '9.9.9.9',
      ]);
    });

    test('an all-IPv6 choice falls back rather than leaving none', () {
      // Dropping every entry would leave an empty list, and no resolver does
      // not mean "no DNS" -- it means the network's own.
      final AdvancedSettings ipv6Only = AdvancedSettings.defaults.copyWith(
        dnsServers: <String>['2606:4700:4700::1111'],
      );

      expect(_dnsServers(_config(_client(), settings: ipv6Only)), <String>[
        '94.140.14.140',
      ]);
    });

    test('the block is never absent', () {
      // An absent dns block does not mean "no DNS" -- it hands resolution to
      // the underlying network, which on these networks both watches and
      // forges it, sending the client to a blockpage before any tunnelled
      // connection is attempted.
      for (final AdvancedSettings settings in <AdvancedSettings>[
        AdvancedSettings.defaults,
        AdvancedSettings.defaults.copyWith(dnsServers: <String>[]),
      ]) {
        final Map<String, dynamic> config = _config(
          _client(),
          settings: settings,
        );
        expect(_dnsServers(config), isNotEmpty);
      }
    });

    test('blank entries never reach the config', () async {
      // ' , 1.1.1.1 , ' is what a person actually types. An empty server in
      // the list is one the core either rejects or silently ignores.
      final ProviderContainer container = _container();

      await container
          .read(advancedSettingsControllerProvider.notifier)
          .setDnsServers(<String>[' ', '1.1.1.1 ', '']);

      expect(
        container.read(advancedSettingsControllerProvider).dnsServers,
        <String>['1.1.1.1'],
      );
    });
  });

  group('multiplexing', () {
    test('turning it on reaches the outbound', () {
      final Map<String, dynamic> mux = _section(
        _outbound(
          _config(
            _client(),
            settings: AdvancedSettings.defaults.copyWith(
              muxEnabled: true,
              muxConcurrency: 4,
            ),
          ),
        ),
        'mux',
      );

      expect(mux['enabled'], isTrue);
      expect(mux['concurrency'], 4);
    });

    test('it does not disturb the rest of the outbound', () {
      // The tag in particular: the plugin reads byte counters by outbound
      // tag, so losing it makes every reading zero -- which looks exactly
      // like a tunnel nobody has used.
      final Map<String, dynamic> withMux = _outbound(
        _config(
          _client(),
          settings: AdvancedSettings.defaults.copyWith(muxEnabled: true),
        ),
      );
      final Map<String, dynamic> without = _outbound(_config(_client()));

      expect(withMux['tag'], 'proxy');
      for (final String key in without.keys.where((String k) => k != 'mux')) {
        expect(withMux[key], without[key], reason: '$key changed');
      }
    });

    test('an out-of-range concurrency cannot reach the config', () async {
      // Xray rejects the whole file rather than the one field, so a bad
      // number does not produce a worse tunnel -- it produces none, reported
      // as a failure to connect with nothing naming the cause.
      final ProviderContainer container = _container();
      final AdvancedSettingsController controller = container.read(
        advancedSettingsControllerProvider.notifier,
      );

      await controller.setMuxConcurrency(0);
      expect(
        container.read(advancedSettingsControllerProvider).muxConcurrency,
        1,
      );

      await controller.setMuxConcurrency(9999);
      expect(
        container.read(advancedSettingsControllerProvider).muxConcurrency,
        128,
      );
    });
  });

  group('sniffing', () {
    test('always means always, including on a plain profile', () {
      expect(
        _section(
          _inbound(
            _config(
              _client(),
              settings: AdvancedSettings.defaults.copyWith(
                sniffing: SniffingMode.always,
              ),
            ),
          ),
          'sniffing',
        )['enabled'],
        isTrue,
      );
    });

    test('never means never, including where rules need it', () {
      // A real consequence, and one the screen says out loud: an ad-block
      // profile stops blocking anything, because there is no name left for
      // its rules to match.
      expect(
        _inbound(
          _config(
            _client(adBlock: true),
            settings: AdvancedSettings.defaults.copyWith(
              sniffing: SniffingMode.never,
            ),
          ),
        ),
        isNot(contains('sniffing')),
      );
    });
  });

  group('IPv6', () {
    test('is not mentioned unless asked for', () {
      // Nothing downstream carries it, so preferring it makes affected names
      // fail slowly rather than work.
      expect(_config(_client()), isNot(contains('routing')));
    });
  });

  group('the access log', () {
    // Found on a real phone. `loglevel` governs the error log only; the
    // access log is a separate key, and unset the core writes a line per
    // connection naming where it went. So every site a person visited was
    // landing in logcat at every log level -- while the screen beside it
    // said nothing about what you visit is recorded.
    test('is off at the levels that promise not to record destinations', () {
      for (final XrayLogLevel level in <XrayLogLevel>[
        XrayLogLevel.none,
        XrayLogLevel.error,
        XrayLogLevel.warning,
      ]) {
        final Map<String, dynamic> log = _section(
          _config(
            _client(),
            settings: AdvancedSettings.defaults.copyWith(logLevel: level),
          ),
          'log',
        );

        expect(
          log['access'],
          'none',
          reason: '$level must not record destinations',
        );
        expect(log['loglevel'], level.wireName);
      }
    });

    test('is left on only where the screen says it is', () {
      // These two options warn that they record every address connected to.
      // Silencing the access log there would make that warning false in the
      // other direction, and would remove the output somebody turned the
      // level up to get.
      for (final XrayLogLevel level in <XrayLogLevel>[
        XrayLogLevel.info,
        XrayLogLevel.debug,
      ]) {
        expect(level.recordsDestinations, isTrue);
        expect(
          _section(
            _config(
              _client(),
              settings: AdvancedSettings.defaults.copyWith(logLevel: level),
            ),
            'log',
          ),
          isNot(contains('access')),
        );
      }
    });

    test('the default config keeps it off', () {
      // The shipped behaviour, and the one that matters: an installation
      // whose owner never opens the advanced screen records nothing.
      expect(_section(_config(_client()), 'log')['access'], 'none');
    });

    test('none is used rather than an empty path', () {
      // The core treats an empty string as a filename. `none` is its own
      // way of saying "do not keep one".
      expect(_section(_config(_client()), 'log')['access'], isNot(''));
    });
  });

  group('the log level', () {
    test('reaches the core', () {
      expect(
        _section(
          _config(
            _client(),
            settings: AdvancedSettings.defaults.copyWith(
              logLevel: XrayLogLevel.error,
            ),
          ),
          'log',
        )['loglevel'],
        'error',
      );
    });

    test('knows which levels record what was visited', () {
      // Surfaced so the screen can warn: info logs a line per connection
      // including its destination, which turns the log into a browsing
      // history on a device that may be inspected.
      expect(XrayLogLevel.info.recordsDestinations, isTrue);
      expect(XrayLogLevel.debug.recordsDestinations, isTrue);
      expect(XrayLogLevel.warning.recordsDestinations, isFalse);
      expect(XrayLogLevel.error.recordsDestinations, isFalse);
      expect(XrayLogLevel.none.recordsDestinations, isFalse);
    });
  });

  group('storage', () {
    test('settings survive a restart', () async {
      final InMemoryAdvancedSettingsStore store =
          InMemoryAdvancedSettingsStore();
      await _container(store)
          .read(advancedSettingsControllerProvider.notifier)
          .setMuxEnabled(enabled: true);

      expect(
        _container(store).read(advancedSettingsControllerProvider).muxEnabled,
        isTrue,
      );
    });

    test('resetting returns every value to its shipped one', () async {
      final ProviderContainer container = _container();
      final AdvancedSettingsController controller = container.read(
        advancedSettingsControllerProvider.notifier,
      );
      await controller.setMuxEnabled(enabled: true);
      await controller.setDnsServers(<String>['9.9.9.9']);
      expect(
        container.read(advancedSettingsControllerProvider).isDefault,
        isFalse,
      );

      await controller.restoreDefaults();

      expect(
        container.read(advancedSettingsControllerProvider).isDefault,
        isTrue,
      );
    });
  });

  group('splitting the handshake', () {
    AdvancedSettings on({
      String packets = 'tlshello',
      String length = '100-200',
      String interval = '10-20',
    }) {
      return AdvancedSettings.defaults.copyWith(
        fragment: FragmentSettings(
          enabled: true,
          packets: packets,
          length: length,
          interval: interval,
        ),
      );
    }

    test('is absent from a default config entirely', () {
      final Map<String, dynamic> config = _config(_client());

      expect(_list(config, 'outbounds'), hasLength(1));
      // streamSettings is always there -- it carries the transport and the
      // TLS name. What must be absent is the sockopt redirect into a
      // fragmenting outbound that does not exist.
      expect(
        _section(_outbound(config), 'streamSettings'),
        isNot(contains('sockopt')),
      );
      expect(jsonEncode(config), isNot(contains('fragment')));
    });

    test('adds an outbound the proxy dials through', () {
      // Two objects, not one field: fragmenting is a property of how the
      // socket is written, which the proxy outbound does not own.
      final Map<String, dynamic> config = _config(_client(), settings: on());
      final List<Map<String, dynamic>> outbounds = _list(config, 'outbounds');

      expect(outbounds, hasLength(2));
      expect(outbounds[1]['tag'], 'fragment');
      expect(outbounds[1]['protocol'], 'freedom');
      expect(
        _section(
          _section(outbounds[0], 'streamSettings'),
          'sockopt',
        )['dialerProxy'],
        'fragment',
      );
    });

    test('carries the three values the core reads', () {
      final Map<String, dynamic> fragment = _section(
        _section(
          _list(
            _config(_client(), settings: on(packets: '1-3')),
            'outbounds',
          )[1],
          'settings',
        ),
        'fragment',
      );

      expect(fragment['packets'], '1-3');
      expect(fragment['length'], '100-200');
      expect(fragment['interval'], '10-20');
    });

    test('does not disturb the transport settings already there', () {
      // The bug this prevents: replacing streamSettings wholesale drops the
      // TLS server name and the transport path, and the tunnel then fails in
      // a way that looks nothing like a fragmentation problem.
      final Map<String, dynamic> stream = _section(
        _outbound(_config(_client(), settings: on())),
        'streamSettings',
      );

      expect(stream['network'], 'xhttp');
      expect(stream['security'], 'tls');
      expect(_section(stream, 'tlsSettings')['serverName'], 'vpn.example.org');
      expect(_section(stream, 'xhttpSettings')['path'], '/xhttp');
    });

    test('the proxy outbound keeps its tag', () {
      // Counters are read by tag. Losing it makes every reading zero, which
      // looks exactly like a tunnel nobody has used.
      expect(_outbound(_config(_client(), settings: on()))['tag'], 'proxy');
    });

    test('it coexists with multiplexing and with ad-blocking', () {
      final Map<String, dynamic> config = _config(
        _client(adBlock: true),
        settings: on().copyWith(muxEnabled: true),
      );
      final List<Map<String, dynamic>> outbounds = _list(config, 'outbounds');

      expect(outbounds.map((Map<String, dynamic> o) => o['tag']), <String>[
        'proxy',
        'fragment',
        'ad-block',
      ]);
      expect(_section(outbounds[0], 'mux')['enabled'], isTrue);
    });
  });

  group('fragment ranges', () {
    test('a plain number and a range are both accepted', () {
      expect(isValidFragmentRange('100'), isTrue);
      expect(isValidFragmentRange('100-200'), isTrue);
    });

    test('nonsense is refused', () {
      for (final String value in <String>[
        '',
        'abc',
        '100-',
        '-200',
        '100-200-300',
        '0',
        '0-200',
        '100,200',
        '1.5',
      ]) {
        expect(
          isValidFragmentRange(value),
          isFalse,
          reason: '$value should not be accepted',
        );
      }
    });

    test('a backwards range is refused', () {
      // It passes a naive pattern and is rejected by the core, which is the
      // worst combination: it looks right and fails later.
      expect(isValidFragmentRange('200-100'), isFalse);
    });

    test('a bad value never reaches the settings', () async {
      final ProviderContainer container = _container();
      final AdvancedSettingsController controller = container.read(
        advancedSettingsControllerProvider.notifier,
      );

      expect(await controller.setFragmentLength('200-100'), isFalse);
      expect(await controller.setFragmentInterval('nope'), isFalse);
      expect(
        container.read(advancedSettingsControllerProvider).fragment.length,
        '100-200',
      );
      expect(
        container.read(advancedSettingsControllerProvider).fragment.interval,
        '10-20',
      );
    });

    test('a good value is taken', () async {
      final ProviderContainer container = _container();

      expect(
        await container
            .read(advancedSettingsControllerProvider.notifier)
            .setFragmentLength('40-80'),
        isTrue,
      );
      expect(
        container.read(advancedSettingsControllerProvider).fragment.length,
        '40-80',
      );
    });
  });

  group('sanctioned services only', () {
    const AdvancedSettings sanctions = AdvancedSettings(
      dnsServers: <String>[],
      muxEnabled: false,
      muxConcurrency: 8,
      sniffing: SniffingMode.whenRoutingNeedsIt,
      logLevel: XrayLogLevel.warning,
      fragment: FragmentSettings.defaults,
      routingMode: RoutingMode.sanctionedOnly,
    );

    List<Map<String, dynamic>> rules(Map<String, dynamic> config) =>
        (_section(config, 'routing')['rules'] as List<dynamic>)
            .cast<Map<String, dynamic>>();

    test('everything mode renders exactly what it rendered before', () {
      // The default must not pay for the feature: no direct outbound, no
      // routing block, nothing a plain profile did not already have.
      final Map<String, dynamic> config = _config(_client());
      expect(
        _list(config, 'outbounds').map((Map<String, dynamic> o) => o['tag']),
        isNot(contains('direct')),
      );
      expect(config.containsKey('routing'), isFalse);
    });

    test(
      'sanctioned domains and DNS go to the server, the rest goes direct',
      () {
        final Map<String, dynamic> config = _config(
          _client(),
          settings: sanctions,
        );

        expect(
          _list(config, 'outbounds').map((Map<String, dynamic> o) => o['tag']),
          containsAll(<String>['proxy', 'direct']),
        );
        final List<Map<String, dynamic>> routing = rules(config);
        expect(routing[0]['outboundTag'], 'proxy');
        expect(routing[0]['domain'], contains('domain:nvidia.com'));
        expect(routing[1], containsPair('port', '53'));
        expect(routing[1]['outboundTag'], 'proxy');
        // Last, and it has to be: Xray sends anything unmatched to its first
        // outbound, which is the server -- the opposite of this mode.
        expect(routing.last['outboundTag'], 'direct');
        expect(routing.last['network'], 'tcp,udp');
      },
    );

    test('ad blocking still wins over the sanctions list', () {
      final Map<String, dynamic> config = _config(
        _client(adBlock: true),
        settings: sanctions,
      );
      expect(rules(config).first['outboundTag'], 'ad-block');
      expect(rules(config).last['outboundTag'], 'direct');
    });

    test('hostnames are read even when sniffing is set to never', () {
      // The mode is nothing but a domain rule; without a hostname every
      // connection would take the direct rule and the tunnel would carry
      // nothing while looking connected.
      final Map<String, dynamic> config = _config(
        _client(),
        settings: sanctions.copyWith(sniffing: SniffingMode.never),
      );
      expect(_inbound(config)['sniffing'], isNotNull);
    });

    test(
      'Hysteria2 is not split, because its client cannot route by domain',
      () {
        const XrayClientResult hysteria = XrayClientResult(
          clientId: 'client-h',
          uuid: '22222222-2222-2222-2222-222222222222',
          serverAddress: 'vpn.example.org',
          port: 443,
          sni: 'vpn.example.org',
          transport: 'hysteria',
          transportSecurity: 'tls',
          adBlock: false,
        );
        expect(routesSanctionsOnly(hysteria, sanctions), isFalse);
        expect(routesSanctionsOnly(_client(), sanctions), isTrue);
      },
    );

    test('Reset restores the tuning but keeps the routing choice', () async {
      final ProviderContainer container = _container();
      final AdvancedSettingsController controller = container.read(
        advancedSettingsControllerProvider.notifier,
      );
      await controller.setRoutingMode(RoutingMode.sanctionedOnly);
      await controller.setMuxEnabled(enabled: true);

      await controller.restoreDefaults();

      final AdvancedSettings after = container.read(
        advancedSettingsControllerProvider,
      );
      expect(after.muxEnabled, isFalse);
      expect(after.routingMode, RoutingMode.sanctionedOnly);
      // And it does not make the Advanced screen read as customised.
      expect(after.isDefault, isTrue);
    });

    test('the choice survives a restart', () async {
      SharedPreferences.setMockInitialValues(<String, Object>{});
      final SharedPreferences preferences =
          await SharedPreferences.getInstance();

      await SharedPreferencesAdvancedSettingsStore(
        preferences,
      ).write(sanctions);

      expect(
        SharedPreferencesAdvancedSettingsStore(preferences).read().routingMode,
        RoutingMode.sanctionedOnly,
      );
    });
  });
}
