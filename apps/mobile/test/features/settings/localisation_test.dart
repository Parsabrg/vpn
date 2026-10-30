/// The app in Persian, and laid out right to left.
///
/// A localisation that is never rendered in the other language is a set of
/// files nobody has checked. These pump the real screen under `fa` and assert
/// what somebody reading Persian actually sees -- including the direction,
/// which is the part that silently breaks a layout built and only ever looked
/// at left to right.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/settings/locale_controller.dart';
import 'package:nebula_mobile/core/storage/locale_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/settings/settings_screen.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../support/localised_app.dart';

Future<ProviderContainer> _container() async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      sharedPreferencesProvider.overrideWithValue(preferences),
      localeStoreProvider.overrideWithValue(InMemoryLocaleStore()),
    ],
  );
  addTearDown(container.dispose);
  return container;
}

Future<void> _pump(
  WidgetTester tester,
  ProviderContainer container, {
  required Locale locale,
}) async {
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: localisedApp(const SettingsScreen(), locale: locale),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('Persian renders Persian, not the English fallback', (
    WidgetTester tester,
  ) async {
    await _pump(tester, await _container(), locale: const Locale('fa'));

    expect(find.text('تنظیمات'), findsOneWidget);
    expect(find.text('Settings'), findsNothing);
  });

  testWidgets('the whole screen is laid out right to left', (
    WidgetTester tester,
  ) async {
    // The half that a translation alone does not give you. Every row on this
    // screen was built and looked at left to right, and a layout that pins
    // something to the left edge stays pinned there under `fa` unless the
    // framework is told the direction -- which is what the Widgets delegate
    // does.
    await _pump(tester, await _container(), locale: const Locale('fa'));

    expect(
      Directionality.of(tester.element(find.text('تنظیمات'))),
      TextDirection.rtl,
    );
  });

  testWidgets('English is still left to right', (WidgetTester tester) async {
    await _pump(tester, await _container(), locale: const Locale('en'));

    expect(find.text('Settings'), findsOneWidget);
    expect(
      Directionality.of(tester.element(find.text('Settings'))),
      TextDirection.ltr,
    );
  });

  testWidgets('a language is offered in its own words', (
    WidgetTester tester,
  ) async {
    // Somebody who has landed in a language they cannot read has to be able
    // to recognise the way out. A list saying "Persian" and "انگلیسی" would
    // be unreadable to exactly that person.
    await _pump(tester, await _container(), locale: const Locale('fa'));

    await tester.tap(find.text('زبان'));
    await tester.pumpAndSettle();

    expect(find.text('English'), findsOneWidget);
    expect(find.text('فارسی'), findsOneWidget);
  });

  testWidgets('choosing a language is remembered', (WidgetTester tester) async {
    final InMemoryLocaleStore store = InMemoryLocaleStore();
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final SharedPreferences preferences = await SharedPreferences.getInstance();
    final ProviderContainer container = ProviderContainer(
      overrides: <Override>[
        sharedPreferencesProvider.overrideWithValue(preferences),
        localeStoreProvider.overrideWithValue(store),
      ],
    );
    addTearDown(container.dispose);

    await _pump(tester, container, locale: const Locale('en'));
    await tester.tap(find.text('Language'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('فارسی'));
    await tester.pumpAndSettle();

    expect(store.readLanguageCode(), 'fa');
    expect(container.read(localeControllerProvider), AppLanguage.persian);
  });

  testWidgets('following the device is a choice, not an absence', (
    WidgetTester tester,
  ) async {
    // Going back has to be as easy as leaving, so "device language" is a row
    // in the list rather than something you get by deselecting.
    final InMemoryLocaleStore store = InMemoryLocaleStore();
    await store.writeLanguageCode('fa');
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final SharedPreferences preferences = await SharedPreferences.getInstance();
    final ProviderContainer container = ProviderContainer(
      overrides: <Override>[
        sharedPreferencesProvider.overrideWithValue(preferences),
        localeStoreProvider.overrideWithValue(store),
      ],
    );
    addTearDown(container.dispose);

    await _pump(tester, container, locale: const Locale('fa'));
    await tester.tap(find.text('زبان'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('زبان دستگاه'));
    await tester.pumpAndSettle();

    expect(store.readLanguageCode(), isNull);
    expect(container.read(localeControllerProvider), isNull);
  });

  testWidgets('dismissing the language sheet keeps the language chosen', (
    WidgetTester tester,
  ) async {
    // "Device language" used to be returned from the sheet as null, which is
    // also what a dismissed sheet returns -- so tapping outside to cancel
    // reset the language to the device's without anybody choosing it.
    final InMemoryLocaleStore store = InMemoryLocaleStore();
    await store.writeLanguageCode('fa');
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final SharedPreferences preferences = await SharedPreferences.getInstance();
    final ProviderContainer container = ProviderContainer(
      overrides: <Override>[
        sharedPreferencesProvider.overrideWithValue(preferences),
        localeStoreProvider.overrideWithValue(store),
      ],
    );
    addTearDown(container.dispose);

    await _pump(tester, container, locale: const Locale('fa'));
    await tester.tap(find.text('زبان'));
    await tester.pumpAndSettle();
    // The barrier above the sheet.
    await tester.tapAt(const Offset(20, 20));
    await tester.pumpAndSettle();

    expect(store.readLanguageCode(), 'fa');
    expect(container.read(localeControllerProvider), AppLanguage.persian);
  });

  test('every language file has a translation for every English key', () {
    // Reads the ARB files, which are the source of truth, rather than the
    // generated classes -- a key missing from a translation is generated with
    // the English string in it, so the generated code cannot tell you it is
    // missing. On screen it shows as one English word in a foreign sentence,
    // which reads as sloppiness rather than as an error.
    final Map<String, dynamic> english = _keys('lib/l10n/app_en.arb');
    for (final File file in _translations()) {
      final Map<String, dynamic> translated = _keys(file.path);
      final List<String> missing = english.keys
          .where((String key) => !translated.containsKey(key))
          .toList();
      expect(
        missing,
        isEmpty,
        reason: 'add these to ${file.path}: ${missing.join(', ')}',
      );
    }
  });

  test('no language file carries a key English has dropped', () {
    // The other direction. A leftover key is dead copy that no reviewer will
    // ever see rendered, so it rots quietly.
    final Map<String, dynamic> english = _keys('lib/l10n/app_en.arb');
    for (final File file in _translations()) {
      expect(
        _keys(file.path).keys.where((String key) => !english.containsKey(key)),
        isEmpty,
        reason: file.path,
      );
    }
  });

  test('counts are written in the digits of the language', () {
    // Persian had "۱ پروتکل" for one and "12 پروتکل" for twelve: the singular
    // is fixed text, and the count was inserted as a plain integer.
    final AppText persian = lookupAppText(const Locale('fa'));
    expect(persian.protocolCount(12), '۱۲ پروتکل');
    expect(persian.protocolCount(1), '۱ پروتکل');
    expect(persian.devicesOfLimit(2, 3), '۲ از ۳ دستگاه');
    expect(persian.latencyMilliseconds(120), '۱۲۰ ms');

    final AppText english = lookupAppText(const Locale('en'));
    expect(english.protocolCount(12), '12 protocols');
    expect(english.devicesOfLimit(2, 3), '2 of 3 devices');
  });

  test('the picker offers exactly the languages the app ships', () {
    // A language file without an entry here is generated, supported, and
    // impossible to choose; an entry without a file shows a name that
    // switches to English.
    expect(
      AppLanguage.values.map((AppLanguage language) => language.code).toSet(),
      AppText.supportedLocales
          .map((Locale locale) => locale.languageCode)
          .toSet(),
    );
  });

  group('resolveAppLocale', () {
    const List<Locale> supported = AppText.supportedLocales;

    test('an unshipped device language falls back to English', () {
      // Not to the first supported locale, which is alphabetical and Arabic.
      expect(
        resolveAppLocale(const <Locale>[Locale('ja')], supported),
        const Locale('en'),
      );
      expect(resolveAppLocale(null, supported), const Locale('en'));
    });

    test('the first shipped language in the device list wins', () {
      expect(
        resolveAppLocale(const <Locale>[Locale('ja'), Locale('de')], supported),
        const Locale('de'),
      );
    });

    test('a regional variant resolves to its language', () {
      expect(
        resolveAppLocale(const <Locale>[Locale('zh', 'TW')], supported),
        const Locale('zh'),
      );
      expect(
        resolveAppLocale(const <Locale>[
          Locale('pt', 'BR'),
          Locale('es', 'MX'),
        ], supported),
        const Locale('es'),
      );
    });
  });
}

/// Every translation, which is every ARB file but the English template.
List<File> _translations() {
  final List<File> files = Directory('lib/l10n')
      .listSync()
      .whereType<File>()
      .where(
        (File f) => f.path.endsWith('.arb') && !f.path.endsWith('app_en.arb'),
      )
      .toList();
  // Guards the guard: an empty list would pass both parity tests above.
  expect(files.length, greaterThanOrEqualTo(9));
  return files;
}

/// The translatable keys of an ARB file: everything but `@@locale` and the
/// `@key` metadata blocks that describe entries for translators.
Map<String, dynamic> _keys(String path) {
  final Map<String, dynamic> raw =
      jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
  return <String, dynamic>{
    for (final MapEntry<String, dynamic> entry in raw.entries)
      if (!entry.key.startsWith('@')) entry.key: entry.value,
  };
}
