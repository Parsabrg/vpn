import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/device_id_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/storage/wireguard_key_store.dart';
import 'package:nebula_mobile/features/devices/devices_screen.dart';

import 'fake_server_repository.dart';

Widget _harness({
  required FakeServerRepository repository,
  String? deviceId = 'device-1',
}) {
  final InMemoryDeviceIdStore deviceIdStore = InMemoryDeviceIdStore();
  if (deviceId != null) {
    deviceIdStore.write(deviceId);
  }
  return ProviderScope(
    overrides: <Override>[
      serverRepositoryProvider.overrideWithValue(repository),
      wireGuardKeyStoreProvider.overrideWithValue(InMemoryWireGuardKeyStore()),
      deviceIdStoreProvider.overrideWithValue(deviceIdStore),
    ],
    child: const MaterialApp(home: DevicesScreen()),
  );
}

void main() {
  testWidgets('shows an honest empty state when nothing is assigned', (
    WidgetTester tester,
  ) async {
    final FakeServerRepository repository = FakeServerRepository();

    await tester.pumpWidget(_harness(repository: repository));
    await tester.pumpAndSettle();

    expect(find.text('No servers assigned yet'), findsOneWidget);
  });

  testWidgets('shows a server/profile picker and a disabled Connect button '
      'until both are chosen', (WidgetTester tester) async {
    final FakeServerRepository repository = FakeServerRepository();
    repository.servers = <AvailableServer>[
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

    await tester.pumpWidget(_harness(repository: repository));
    await tester.pumpAndSettle();

    // Nothing is selected yet, so the field shows its hint, not a server
    // name -- that only appears once the dropdown is opened or chosen.
    expect(find.text('Choose a server'), findsOneWidget);
    final FilledButton connectButton = tester.widget<FilledButton>(
      find.widgetWithText(FilledButton, 'Connect'),
    );
    expect(connectButton.onPressed, isNull);
  });

  testWidgets('shows the peer configuration and a Disconnect action once '
      'connected', (WidgetTester tester) async {
    final FakeServerRepository repository = FakeServerRepository();
    repository.servers = <AvailableServer>[
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
    repository.requestPeerResult = const WireGuardPeerResult(
      peerId: 'peer-1',
      assignedAddress: '10.77.0.2',
      serverPublicKey: 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS=',
      listenPort: 51820,
      publicEndpoint: 'vps1.example.test:51820',
      clientDns: '10.77.0.1',
      clientAllowedIps: '0.0.0.0/0,::/0',
      persistentKeepaliveSeconds: 25,
    );

    await tester.pumpWidget(_harness(repository: repository));
    await tester.pumpAndSettle();

    // Tap the dropdown field itself, not its hint text -- the hint sits
    // inside the field's InputDecorator, which doesn't forward hits to the
    // dropdown's own tap target.
    final Finder serverDropdown = find.byType(DropdownButtonFormField<String>);
    await tester.tap(serverDropdown);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Amsterdam 1').last);
    await tester.pumpAndSettle();

    final Finder profileDropdown = find
        .byType(DropdownButtonFormField<String>)
        .last;
    await tester.tap(profileDropdown);
    await tester.pumpAndSettle();
    await tester.tap(find.text('WireGuard default').last);
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(FilledButton, 'Connect'));
    await tester.pumpAndSettle();

    expect(find.text('WireGuard peer provisioned'), findsOneWidget);
    expect(find.text('10.77.0.2'), findsOneWidget);
    expect(find.widgetWithText(FilledButton, 'Disconnect'), findsOneWidget);
  });
}
