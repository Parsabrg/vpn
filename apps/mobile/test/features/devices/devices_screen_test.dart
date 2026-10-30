import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/account/account_repository.dart';
import 'package:nebula_mobile/core/storage/locale_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/devices/devices_screen.dart';

import '../../core/account/fake_account_repository.dart';
import '../../support/localised_app.dart';

// This screen used to be the connect flow. That moved to features/connect,
// and its states are covered by connect_view_test and connect_screen_test;
// the flow through the controller stays covered by devices_controller_test.
// What is tested here is what this screen became: view and revoke.

const String _thisDeviceId = 'device-this';
const String _otherDeviceId = 'device-other';

AccountDevice _device({
  required String id,
  required String name,
  bool isCurrent = false,
  List<String> serverCodes = const <String>[],
  String platform = 'android',
}) {
  return AccountDevice(
    id: id,
    name: name,
    platform: platform,
    state: 'active',
    clientVersion: '0.1.6',
    registeredAt: DateTime.utc(2026, 9, 2, 10),
    isCurrent: isCurrent,
    serverCodes: serverCodes,
  );
}

FakeAccountRepository _repository({List<AccountDevice>? devices}) {
  final List<AccountDevice> list =
      devices ??
      <AccountDevice>[
        _device(
          id: _thisDeviceId,
          name: 'Pixel 8',
          isCurrent: true,
          serverCodes: <String>['de-fra-1'],
        ),
        _device(
          id: _otherDeviceId,
          name: 'Windows desktop',
          platform: 'windows',
          serverCodes: <String>['nl-ams-1'],
        ),
      ];
  return FakeAccountRepository()
    ..devices = list
    ..account = AccountSummary(
      email: 'owner@example.org',
      username: 'owner',
      state: 'active',
      deviceLimit: 5,
      devicesInUse: list.length,
      usedBytes: 0,
    );
}

Future<void> _pump(
  WidgetTester tester,
  FakeAccountRepository repository,
) async {
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        accountRepositoryProvider.overrideWithValue(repository),
        // A failed load writes its message in the app's language, read from
        // a store that would otherwise reach SharedPreferences.
        localeStoreProvider.overrideWithValue(InMemoryLocaleStore()),
      ],
      child: localisedApp(const DevicesScreen()),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('lists the devices with the count from the same load', (
    WidgetTester tester,
  ) async {
    await _pump(tester, _repository());

    expect(find.text('Pixel 8'), findsOneWidget);
    expect(find.text('Windows desktop'), findsOneWidget);
    expect(find.text('2 of 5'), findsOneWidget);
  });

  testWidgets('marks this device and says where its peer is', (
    WidgetTester tester,
  ) async {
    await _pump(tester, _repository());
    expect(find.text('this device · peer on de-fra-1'), findsOneWidget);
  });

  testWidgets('a device with no credential says so, not a server name', (
    WidgetTester tester,
  ) async {
    await _pump(
      tester,
      _repository(
        devices: <AccountDevice>[
          _device(id: _thisDeviceId, name: 'Pixel 8', isCurrent: true),
        ],
      ),
    );
    expect(find.textContaining('no peer'), findsOneWidget);
  });

  testWidgets('only the other device offers Revoke', (
    WidgetTester tester,
  ) async {
    // Revoking the device you are holding would drop your own tunnel, and the
    // API refuses it. The row must not offer an action that cannot succeed.
    await _pump(tester, _repository());
    expect(find.text('Revoke'), findsOneWidget);
  });

  testWidgets('revoking asks first, and cancelling changes nothing', (
    WidgetTester tester,
  ) async {
    final FakeAccountRepository repository = _repository();
    await _pump(tester, repository);

    await tester.tap(find.text('Revoke'));
    await tester.pumpAndSettle();
    expect(find.text('Revoke Windows desktop?'), findsOneWidget);

    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(repository.revoked, isEmpty);
    expect(find.text('Windows desktop'), findsOneWidget);
  });

  testWidgets('confirming revokes and the count follows the list', (
    WidgetTester tester,
  ) async {
    // The header and the rows come from one load, so they cannot disagree
    // after a revoke -- which is the whole reason one controller owns both.
    final FakeAccountRepository repository = _repository();
    await _pump(tester, repository);

    await tester.tap(find.text('Revoke'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(TextButton, 'Revoke').last);
    await tester.pumpAndSettle();

    expect(repository.revoked, <String>[_otherDeviceId]);
    expect(find.text('Windows desktop'), findsNothing);
    expect(find.text('1 of 5'), findsOneWidget);
  });

  testWidgets('a failed load offers a retry rather than an empty list', (
    WidgetTester tester,
  ) async {
    final FakeAccountRepository repository = _repository()
      ..accountError = Exception('offline');
    await _pump(tester, repository);

    expect(find.text('NO CONNECTION'), findsOneWidget);
    expect(find.text('Try again'), findsOneWidget);
  });

  testWidgets('says what revoking actually does', (WidgetTester tester) async {
    await _pump(tester, _repository());
    expect(find.textContaining('signs out on next refresh'), findsOneWidget);
  });
}
