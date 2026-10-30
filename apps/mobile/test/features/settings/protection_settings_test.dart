import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/app_info.dart';
import 'package:nebula_mobile/core/settings/protection_controller.dart';
import 'package:nebula_mobile/core/storage/protection_preference_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/core/widgets/panel/panel_controls.dart';
import 'package:nebula_mobile/core/window/login_item.dart';
import 'package:nebula_mobile/features/settings/settings_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../support/localised_app.dart';

class _FakeLoginItem implements LoginItem {
  bool on = false;

  @override
  Future<bool> enabled() async => on;

  @override
  Future<void> set({required bool enabled}) async => on = enabled;
}

Future<ProviderContainer> _container({
  ProtectionPreferenceStore? store,
  LoginItem? loginItem,
  ({bool alwaysOn, bool lockdown})? killSwitch,
}) async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  return ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
      if (store != null)
        protectionPreferenceStoreProvider.overrideWithValue(store),
      // The real one asks the registry, or the home directory.
      loginItemProvider.overrideWithValue(loginItem ?? _FakeLoginItem()),
      // A platform channel otherwise; what the tunnel last read from Android.
      androidKillSwitchProvider.overrideWith((Ref ref) async => killSwitch),
    ],
  );
}

Future<void> _pump(WidgetTester tester, ProviderContainer container) async {
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: localisedApp(const SettingsScreen()),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  group('protection preferences', () {
    test('an unset preference reads as the default, not as off', () {
      // getBool returns null for a key never written. Treating that as false
      // would silently ship both protections disabled to every existing
      // install on first upgrade.
      final InMemoryProtectionStore store = InMemoryProtectionStore();
      expect(store.read(), ProtectionPreferences.defaults);
      expect(ProtectionPreferences.defaults.connectOnLaunch, isTrue);
      expect(ProtectionPreferences.defaults.notificationSpeed, isTrue);
      // Only ever restores a connection somebody left on.
      expect(ProtectionPreferences.defaults.reconnectAfterRestart, isTrue);
    });

    testWidgets('toggling writes through to the store', (
      WidgetTester tester,
    ) async {
      final InMemoryProtectionStore store = InMemoryProtectionStore();
      final ProviderContainer container = await _container(store: store);
      addTearDown(container.dispose);
      await _pump(tester, container);

      await tester.tap(find.text('Connect on launch'));
      await tester.pumpAndSettle();

      expect(
        container.read(protectionControllerProvider).connectOnLaunch,
        isFalse,
      );
      expect(store.read().connectOnLaunch, isFalse);
      // The other one must not have moved with it.
      expect(store.read().notificationSpeed, isTrue);
    });

    testWidgets('the whole row is the target, not just the switch', (
      WidgetTester tester,
    ) async {
      // A 28px switch in the corner of a row is a poor target; tapping the
      // label is what most people will actually do.
      final InMemoryProtectionStore store = InMemoryProtectionStore();
      final ProviderContainer container = await _container(store: store);
      addTearDown(container.dispose);
      await _pump(tester, container);

      await tester.tap(find.text('live ↓ ↑ in the shade'));
      await tester.pumpAndSettle();

      expect(store.read().notificationSpeed, isFalse);
    });
  });

  group('kill switch', () {
    testWidgets('is a row, not a toggle', (WidgetTester tester) async {
      // Android owns the setting. A switch here would promise a protection
      // this app cannot deliver.
      final ProviderContainer container = await _container();
      addTearDown(container.dispose);
      await _pump(tester, container);
      // Scrolled to rather than assumed on screen: the settings list is
      // longer than the viewport, and the language row pushed this below it.
      await tester.scrollUntilVisible(find.text('Kill switch'), 200);

      expect(find.text('Kill switch'), findsOneWidget);
      // With no tunnel up there is nothing that can ask Android.
      expect(
        find.text('Android setting · shown while connected'),
        findsOneWidget,
      );
      // No switch in the row itself. Counting every switch on the screen used
      // to stand in for this, and broke each time a toggle was added: the list
      // is built lazily, so rows scrolled past are not there to count.
      final Finder row = find.ancestor(
        of: find.text('Kill switch'),
        matching: find.byType(PanelExternalRow),
      );
      expect(row, findsOneWidget);
      expect(
        find.descendant(of: row, matching: find.byType(Switch)),
        findsNothing,
      );
    });

    testWidgets('says what Android has switched on', (
      WidgetTester tester,
    ) async {
      // It used to say "off" without asking, on a phone with both on.
      for (final (({bool alwaysOn, bool lockdown}) state, String shown)
          in <(({bool alwaysOn, bool lockdown}), String)>[
            ((alwaysOn: true, lockdown: true), 'Android setting · on'),
            (
              (alwaysOn: true, lockdown: false),
              'Android setting · always-on, not blocking',
            ),
            ((alwaysOn: false, lockdown: false), 'Android setting · off'),
          ]) {
        final ProviderContainer container = await _container(killSwitch: state);
        await _pump(tester, container);
        await tester.scrollUntilVisible(find.text('Kill switch'), 200);
        expect(find.text(shown), findsOneWidget, reason: '$state');
        await tester.pumpWidget(const SizedBox());
        container.dispose();
      }
    });

    testWidgets('is a toggle of the app on the desktop', (
      WidgetTester tester,
    ) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.windows;
      addTearDown(() => debugDefaultTargetPlatformOverride = null);
      final ProviderContainer container = await _container();
      addTearDown(container.dispose);
      await _pump(tester, container);
      await tester.scrollUntilVisible(find.text('Kill switch'), 200);
      await tester.ensureVisible(find.text('Kill switch'));
      await tester.pumpAndSettle();

      expect(find.text('block the internet if the VPN drops'), findsOneWidget);
      expect(find.text('Android setting · off'), findsNothing);
      await tester.tap(find.text('Kill switch'));
      await tester.pumpAndSettle();
      expect(
        container.read(protectionControllerProvider).blockWhenVpnDrops,
        isTrue,
      );
      debugDefaultTargetPlatformOverride = null;
    });

    testWidgets('the desktop starts at sign-in where Android reconnects', (
      WidgetTester tester,
    ) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.windows;
      addTearDown(() => debugDefaultTargetPlatformOverride = null);
      final _FakeLoginItem item = _FakeLoginItem();
      final ProviderContainer container = await _container(loginItem: item);
      addTearDown(container.dispose);
      await _pump(tester, container);

      // Android's restart receiver has no desktop counterpart.
      expect(find.text('Reconnect after restart'), findsNothing);
      await tester.tap(find.text('Start when you sign in'));
      await tester.pumpAndSettle();
      expect(item.on, isTrue);
      // Read back from the system, not assumed.
      expect(container.read(loginItemEnabledProvider).value, isTrue);
      debugDefaultTargetPlatformOverride = null;
    });

    test('a Linux sign-in entry quotes its path', () {
      expect(
        linuxAutostartEntry(r'/home/a b/Nebula$VPN.AppImage'),
        contains(r'Exec="/home/a b/Nebula\$VPN.AppImage"'),
      );
      expect(
        linuxAutostartFile(<String, String>{'HOME': '/home/u'}).path,
        '/home/u/.config/autostart/nebula-vpn.desktop',
      );
      expect(
        linuxAutostartFile(<String, String>{
          'HOME': '/home/u',
          'XDG_CONFIG_HOME': '/cfg',
        }).path,
        '/cfg/autostart/nebula-vpn.desktop',
      );
    });

    testWidgets('explains before sending you to Android', (
      WidgetTester tester,
    ) async {
      final ProviderContainer container = await _container();
      addTearDown(container.dispose);
      await _pump(tester, container);
      await tester.scrollUntilVisible(find.text('Kill switch'), 200);
      // Scrolled wholly into view, not just onto the screen's edge: another
      // row above it left the tap landing off the bottom of the viewport.
      await tester.ensureVisible(find.text('Kill switch'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Kill switch'));
      await tester.pumpAndSettle();

      expect(find.textContaining('Always-on VPN'), findsOneWidget);
      expect(find.text('Open Android VPN settings'), findsOneWidget);

      await tester.tap(find.text('Not now'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Always-on VPN'), findsNothing);
    });
  });

  testWidgets('shows the release version, not a build placeholder', (
    WidgetTester tester,
  ) async {
    final ProviderContainer container = await _container();
    addTearDown(container.dispose);
    await _pump(tester, container);

    // Scrolled to, not assumed on screen: the settings list is longer than
    // the viewport, and a lazily built ListView has not created the About
    // section until it is reached.
    await tester.scrollUntilVisible(find.text('Version'), 200);

    expect(find.text('Version'), findsOneWidget);
    // kClientVersion, which app_info_test pins to pubspec.yaml, so it cannot
    // go stale. This used to read a NEBULA_VERSION build define that no
    // build script ever passed, so every shipped APK said "dev".
    expect(find.text(kClientVersion), findsOneWidget);
  });
}
