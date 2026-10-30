/// Routing chosen apps around the tunnel.
///
/// The risk this carries is one-directional: an app the user believes is
/// excluded but is not costs them privacy they thought they had turned off,
/// while an app excluded by mistake only costs them the tunnel. So most of
/// what follows checks that the selection reaches the two backends exactly as
/// made, and that nothing silently widens it.
library;

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/split_tunnel/split_tunnel_controller.dart';
import 'package:nebula_mobile/core/storage/split_tunnel_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/wireguard/wireguard_config.dart';

ProviderContainer _container([SplitTunnelStore? store]) {
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      splitTunnelStoreProvider.overrideWithValue(
        store ?? InMemorySplitTunnelStore(),
      ),
    ],
  );
  addTearDown(container.dispose);
  return container;
}

const WireGuardPeerResult _peer = WireGuardPeerResult(
  peerId: 'peer-1',
  assignedAddress: '10.77.0.2',
  serverPublicKey: 'server-key',
  listenPort: 51820,
  publicEndpoint: 'vpn.example.org:51820',
  clientDns: '1.1.1.1',
  clientAllowedIps: '0.0.0.0/0',
  persistentKeepaliveSeconds: 25,
);

String _config({List<String> excluded = const <String>[]}) {
  return withExcludedApplications(
    renderWireGuardConfig(privateKeyBase64: 'private-key', peer: _peer),
    excluded,
  );
}

void main() {
  group('the selection', () {
    test('starts empty, so a fresh install tunnels everything', () {
      // The safe default for a tool whose whole job is to carry traffic.
      expect(_container().read(splitTunnelControllerProvider), isEmpty);
    });

    test('excluding and un-excluding an app round trips', () async {
      final ProviderContainer container = _container();
      final SplitTunnelController controller = container.read(
        splitTunnelControllerProvider.notifier,
      );

      await controller.setExcluded('com.bank.app', excluded: true);
      expect(controller.isExcluded('com.bank.app'), isTrue);

      await controller.setExcluded('com.bank.app', excluded: false);
      expect(controller.isExcluded('com.bank.app'), isFalse);
    });

    test('survives a restart', () async {
      final InMemorySplitTunnelStore store = InMemorySplitTunnelStore();
      await _container(store)
          .read(splitTunnelControllerProvider.notifier)
          .setExcluded('com.bank.app', excluded: true);

      // A second container over the same storage is what the next launch is.
      expect(_container(store).read(splitTunnelControllerProvider), <String>{
        'com.bank.app',
      });
    });

    test('emptying the list is remembered, not treated as unset', () async {
      // The bug this prevents: remove every exclusion, restart, and find
      // them all back because "empty" was stored as "nothing was chosen".
      final InMemorySplitTunnelStore store = InMemorySplitTunnelStore();
      final SplitTunnelController controller = _container(
        store,
      ).read(splitTunnelControllerProvider.notifier);
      await controller.setExcluded('com.bank.app', excluded: true);

      await controller.clear();

      expect(_container(store).read(splitTunnelControllerProvider), isEmpty);
    });

    test('is handed to the backends in a stable order', () {
      // Two identical selections must render identical configs; a Set
      // iterating differently between runs would make them compare unequal
      // and churn the stored value on every write.
      expect(excludedPackagesFor(<String>{'b.app', 'a.app', 'c.app'}), <String>[
        'a.app',
        'b.app',
        'c.app',
      ]);
    });
  });

  group('the WireGuard config', () {
    test('is unchanged when nothing is excluded', () {
      // Not an empty key: `ExcludedApplications = ` is not the same as
      // absent, and the parser is entitled to treat it as a malformed line.
      expect(_config(), isNot(contains('ExcludedApplications')));
    });

    test('carries the excluded packages', () {
      final String config = _config(
        excluded: <String>['com.bank.app', 'com.maps.app'],
      );

      expect(
        config,
        contains('ExcludedApplications = com.bank.app, com.maps.app'),
      );
    });

    test('puts the key under [Interface], not [Peer]', () {
      // ExcludedApplications is an Interface key. Appended to the end of the
      // file it lands under [Peer], where it is silently ignored -- the
      // tunnel comes up looking correct and excludes nothing.
      final String config = _config(excluded: <String>['com.bank.app']);

      expect(
        config.indexOf('ExcludedApplications'),
        lessThan(config.indexOf('[Peer]')),
      );
      expect(
        config.indexOf('[Interface]'),
        lessThan(config.indexOf('ExcludedApplications')),
      );
    });

    test('keeps every key the tunnel already needed', () {
      final String config = _config(excluded: <String>['com.bank.app']);

      expect(config, contains('PrivateKey = private-key'));
      expect(config, contains('Address = 10.77.0.2/32'));
      expect(config, contains('PublicKey = server-key'));
      expect(config, contains('Endpoint = vpn.example.org:51820'));
      expect(config, contains('PersistentKeepalive = 25'));
    });

    test('the inserted key is on a line of its own', () {
      // Run onto the end of `DNS = ...` it is not a key at all, and the
      // parser either rejects the file or ignores the line.
      final List<String> lines = _config(
        excluded: <String>['com.bank.app'],
      ).split('\n');

      expect(lines, contains('ExcludedApplications = com.bank.app'));
    });
  });
}
