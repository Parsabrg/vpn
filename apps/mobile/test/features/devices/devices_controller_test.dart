import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/storage/wireguard_key_store.dart';
import 'package:nebula_mobile/features/devices/devices_controller.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';

import 'fake_server_repository.dart';

const String _deviceId = 'device-1';

WireGuardPeerResult _peerResult() {
  return const WireGuardPeerResult(
    peerId: 'peer-1',
    assignedAddress: '10.77.0.2',
    serverPublicKey: 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS=',
    listenPort: 51820,
    publicEndpoint: 'vps1.example.test:51820',
    clientDns: '10.77.0.1',
    clientAllowedIps: '0.0.0.0/0,::/0',
    persistentKeepaliveSeconds: 25,
  );
}

({
  ProviderContainer container,
  FakeServerRepository repository,
  InMemoryWireGuardKeyStore keyStore,
})
_harness() {
  final FakeServerRepository repository = FakeServerRepository();
  final InMemoryWireGuardKeyStore keyStore = InMemoryWireGuardKeyStore();
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      serverRepositoryProvider.overrideWithValue(repository),
      wireGuardKeyStoreProvider.overrideWithValue(keyStore),
    ],
  );
  return (container: container, repository: repository, keyStore: keyStore);
}

void main() {
  group('DevicesController.load', () {
    test('populates servers on success', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.servers = <AvailableServer>[
        const AvailableServer(
          code: 'ams-1',
          displayName: 'Amsterdam 1',
          publicHost: 'ams-1.example.test',
          profiles: <AvailableProfile>[
            AvailableProfile(
              code: 'wg-default',
              displayName: 'WireGuard default',
              protocolId: 'protocol-1',
            ),
          ],
        ),
      ];

      await harness.container.read(devicesControllerProvider.notifier).load();

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.loadStatus, DevicesLoadStatus.loaded);
      expect(state.servers, hasLength(1));
    });

    test('surfaces a generic message on failure', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      harness.repository.listError = const NebulaApiException(
        statusCode: 500,
        detail: 'Request was not accepted',
      );

      await harness.container.read(devicesControllerProvider.notifier).load();

      final DevicesState state = harness.container.read(
        devicesControllerProvider,
      );
      expect(state.loadStatus, DevicesLoadStatus.failed);
      expect(state.loadErrorMessage, isNotNull);
    });
  });

  group('DevicesController.connect', () {
    test('does nothing without both a server and profile selected', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );

      await notifier.connect(_deviceId);

      expect(harness.repository.requestPeerCalls, 0);
    });

    test(
      'sends a freshly generated public key and stores the peer result',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(harness.repository.requestPeerCalls, 1);
        expect(harness.repository.lastRequestedServerCode, 'ams-1');
        expect(harness.repository.lastRequestedPublicKey, isNotEmpty);
        expect(state.isConnected, isTrue);
        expect(state.connectedServerCode, 'ams-1');
        // The generated private key must have been persisted so a later
        // connect attempt reuses this device's identity instead of minting a
        // new one.
        expect(await harness.keyStore.readPrivateKey(), isNotNull);
      },
    );

    test(
      'reuses an existing stored key instead of generating a new one',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        await harness.keyStore.writePrivateKey(
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        );
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();

        await notifier.connect(_deviceId);

        expect(
          await harness.keyStore.readPrivateKey(),
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        );
      },
    );

    test(
      'a failed request surfaces an error and leaves the peer unset',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerError = const NebulaApiException(
          statusCode: 409,
          detail: 'Device already has a WireGuard peer',
        );

        await notifier.connect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isFalse);
        expect(state.actionErrorMessage, 'Device already has a WireGuard peer');
      },
    );
  });

  group('DevicesController.disconnect', () {
    test(
      'clears the peer and calls revoke with the connected server code',
      () async {
        final harness = _harness();
        addTearDown(harness.container.dispose);
        final DevicesController notifier = harness.container.read(
          devicesControllerProvider.notifier,
        );
        notifier.selectServer('ams-1');
        notifier.selectProfile('wg-default');
        harness.repository.requestPeerResult = _peerResult();
        await notifier.connect(_deviceId);

        await notifier.disconnect(_deviceId);

        final DevicesState state = harness.container.read(
          devicesControllerProvider,
        );
        expect(state.isConnected, isFalse);
        expect(harness.repository.revokePeerCalls, 1);
        expect(harness.repository.lastRevokedServerCode, 'ams-1');
      },
    );

    test('does nothing when there is no connected server', () async {
      final harness = _harness();
      addTearDown(harness.container.dispose);
      final DevicesController notifier = harness.container.read(
        devicesControllerProvider.notifier,
      );

      await notifier.disconnect(_deviceId);

      expect(harness.repository.revokePeerCalls, 0);
    });
  });
}
