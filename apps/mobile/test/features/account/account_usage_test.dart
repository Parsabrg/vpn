import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/account/account_repository.dart';
import 'package:nebula_mobile/core/format/bytes.dart';
import 'package:nebula_mobile/core/network/api_exception.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/theme/color_tokens.dart';
import 'package:nebula_mobile/features/account/account_controller.dart';
import 'package:nebula_mobile/features/account/account_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/account/fake_account_repository.dart';
import '../../support/localised_app.dart';

const int kib = 1024;
const int mib = kib * 1024;
const int gib = mib * 1024;

AccountSummary _account({
  required int usedBytes,
  int? lifetimeBytes,
  int? quotaBytes,
  int? remainingBytes,
}) {
  return AccountSummary(
    email: 'owner@example.org',
    username: 'owner',
    state: 'active',
    deviceLimit: 5,
    devicesInUse: 2,
    usedBytes: usedBytes,
    lifetimeBytes: lifetimeBytes,
    quotaBytes: quotaBytes,
    remainingBytes: remainingBytes,
  );
}

Future<void> _pump(WidgetTester tester, AccountSummary account) async {
  final FakeAccountRepository repository = FakeAccountRepository()
    ..account = account;
  // The details view watches the auth notifier for the session id, and that
  // reaches SharedPreferences -- which throws unless overridden, by design.
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        accountRepositoryProvider.overrideWithValue(repository),
        sharedPreferencesProvider.overrideWithValue(preferences),
      ],
      child: localisedApp(const AccountScreen()),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('settings stay reachable when the account cannot load', (
    WidgetTester tester,
  ) async {
    // Seen on a phone: with the server unreachable, the whole screen became
    // "You're offline" and Settings -- which need no server -- went with it.
    final FakeAccountRepository repository = FakeAccountRepository()
      ..accountError = const NebulaConnectivityException('offline');
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final SharedPreferences preferences = await SharedPreferences.getInstance();
    await tester.pumpWidget(
      ProviderScope(
        overrides: <Override>[
          accountRepositoryProvider.overrideWithValue(repository),
          sharedPreferencesProvider.overrideWithValue(preferences),
        ],
        child: localisedApp(const AccountScreen()),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Try again'), findsOneWidget);
    expect(find.text('Settings'), findsOneWidget);
  });

  group('formatBytes', () {
    test('bytes below a kilobyte are exact', () {
      expect(formatBytes(0), '0 B');
      expect(formatBytes(999), '999 B');
    });

    test('one decimal below ten, none above', () {
      // 412.7 GB is no more useful than 412 GB and is wider in a column.
      expect(formatBytes((1.4 * gib).round()), '1.4 GB');
      expect(formatBytes(412 * gib), '412 GB');
    });

    test('uses binary units, matching what the servers count in', () {
      // 1000 MB is not a gigabyte here. Mixing conventions is how a "1 GB"
      // allowance becomes an argument about 7 per cent of it.
      expect(formatBytes(gib), '1.0 GB');
      expect(formatBytes(1000 * mib), '1000 MB');
    });

    test('a negative count never renders as a negative size', () {
      expect(formatBytes(-5), '0 B');
    });
  });

  group('formatBytePair', () {
    test('renders both figures in the same unit', () {
      // "860 MB / 1.0 GB" makes the reader do a subtraction across units.
      expect(formatBytePair(860 * mib, gib), '860 / 1024 MB');
    });

    test('a fresh account does not fall back to kilobytes', () {
      // With nothing used the unit comes from the total instead, or a new
      // account would read "0 / 1073741824 KB".
      expect(formatBytePair(0, gib), '0 / 1 GB');
    });

    test('matches the design\'s used-of-total line', () {
      expect(formatBytePair(612 * gib, 1024 * gib), '612 / 1024 GB');
    });
  });

  group('lifetimeBytes', () {
    test('is the allowance figure from a server that does not report it', () {
      expect(_account(usedBytes: 3 * gib).lifetimeBytes, 3 * gib);
    });
  });

  group('usedFraction', () {
    test('is null when unmetered so no bar is drawn', () {
      // A bar for an account with no limit would state something untrue
      // whichever way it was drawn.
      expect(_account(usedBytes: gib).usedFraction, isNull);
    });

    test('clamps at one when over quota', () {
      final AccountSummary account = _account(
        usedBytes: 5 * gib,
        quotaBytes: 2 * gib,
        remainingBytes: 0,
      );
      expect(account.usedFraction, 1.0);
    });
  });

  group('the account screen', () {
    testWidgets('a metered account leads with what is left', (
      WidgetTester tester,
    ) async {
      await _pump(
        tester,
        _account(
          usedBytes: 612 * gib,
          quotaBytes: 1024 * gib,
          remainingBytes: 412 * gib,
        ),
      );

      expect(find.text('412 GB'), findsOneWidget);
      expect(find.text('left'), findsOneWidget);
      expect(find.text('612 / 1024 GB used'), findsOneWidget);
      // Nothing was used before this allowance, so the total adds nothing.
      expect(find.textContaining('in total'), findsNothing);
    });

    testWidgets('a metered account also shows what it used before', (
      WidgetTester tester,
    ) async {
      // An allowance granted on top of earlier use starts "used" again; the
      // all-time figure must not start again with it.
      await _pump(
        tester,
        _account(
          usedBytes: 612 * gib,
          lifetimeBytes: 800 * gib,
          quotaBytes: 1024 * gib,
          remainingBytes: 412 * gib,
        ),
      );

      expect(find.text('612 / 1024 GB used'), findsOneWidget);
      expect(find.text('800 GB used in total'), findsOneWidget);
    });

    testWidgets('an unmetered account shows everything it ever used', (
      WidgetTester tester,
    ) async {
      // Not what has been used since an allowance was last removed.
      await _pump(
        tester,
        _account(usedBytes: 100 * kib, lifetimeBytes: (2.4 * gib).round()),
      );

      expect(find.text('2.4 GB'), findsOneWidget);
      expect(find.text('100 KB'), findsNothing);
    });

    testWidgets('an unmetered account shows the total and says so', (
      WidgetTester tester,
    ) async {
      // Not a bar at zero, and not an invented allowance.
      await _pump(tester, _account(usedBytes: 3 * gib));

      expect(find.text('3.0 GB'), findsOneWidget);
      expect(find.text('used · no limit'), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsNothing);
    });

    testWidgets('an exhausted allowance reads as amber, not as an error', (
      WidgetTester tester,
    ) async {
      // Running out of traffic is a state worth noticing, not a failure --
      // red is reserved for unreachable.
      await _pump(
        tester,
        _account(usedBytes: 2 * gib, quotaBytes: 2 * gib, remainingBytes: 0),
      );

      expect(find.text('nothing left'), findsOneWidget);
      final Text figure = tester.widget<Text>(find.text('0 B'));
      expect(figure.style?.color, NebulaPalette.dark.amberText);
      expect(figure.style?.color, isNot(NebulaPalette.dark.red));
    });
  });

  group('keeping the figures current', () {
    const Duration interval = Duration(seconds: 30);

    Future<FakeAccountRepository> pumpScreen(
      WidgetTester tester,
      AccountSummary account, {
      bool visible = true,
    }) async {
      final FakeAccountRepository repository = FakeAccountRepository()
        ..account = account;
      SharedPreferences.setMockInitialValues(<String, Object>{});
      final SharedPreferences preferences =
          await SharedPreferences.getInstance();
      await tester.pumpWidget(
        ProviderScope(
          overrides: <Override>[
            accountRepositoryProvider.overrideWithValue(repository),
            sharedPreferencesProvider.overrideWithValue(preferences),
            accountRefreshIntervalProvider.overrideWithValue(interval),
          ],
          // A hidden tab is how go_router keeps the other branches: built,
          // offstage, and with tickers turned off.
          child: localisedApp(
            TickerMode(enabled: visible, child: const AccountScreen()),
          ),
        ),
      );
      await tester.pumpAndSettle();
      return repository;
    }

    testWidgets('a showing screen fetches the figures again', (
      WidgetTester tester,
    ) async {
      // Loaded once and never again, the screen said "0 / 30 MB used" for
      // twenty minutes after the allowance was spent.
      final FakeAccountRepository repository = await pumpScreen(
        tester,
        _account(usedBytes: 0, quotaBytes: 30 * mib, remainingBytes: 30 * mib),
      );
      expect(find.text('0 / 30 MB used'), findsOneWidget);

      repository.account = _account(
        usedBytes: 30 * mib,
        quotaBytes: 30 * mib,
        remainingBytes: 0,
      );
      await tester.pump(interval);
      await tester.pumpAndSettle();

      expect(find.text('nothing left'), findsOneWidget);
      expect(find.text('30 / 30 MB used'), findsOneWidget);
    });

    testWidgets('a hidden tab fetches nothing', (WidgetTester tester) async {
      final FakeAccountRepository repository = await pumpScreen(
        tester,
        _account(usedBytes: gib),
        visible: false,
      );

      await tester.pump(interval * 3);

      expect(repository.fetchAccountCalls, 0);
    });

    testWidgets('a refresh that fails keeps the last figures', (
      WidgetTester tester,
    ) async {
      // A dropped request is not a reason to replace good figures with an
      // error.
      final FakeAccountRepository repository = await pumpScreen(
        tester,
        _account(usedBytes: 3 * gib),
      );
      repository.accountError = Exception('offline');

      await tester.pump(interval);
      await tester.pumpAndSettle();

      expect(repository.fetchAccountCalls, 2);
      expect(find.text('3.0 GB'), findsOneWidget);
    });
  });
}
