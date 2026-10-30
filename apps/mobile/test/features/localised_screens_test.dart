/// Every screen, rendered in every translation, showing no English copy.
///
/// The ARB parity test proves each English string has a translation. It
/// cannot prove a screen asks for it: a widget that still hardcodes `'Sign in'`
/// passes that test and ships English into a Russian or Arabic screen. This
/// one renders each screen in each language and fails on any visible text
/// that is, word for word, an English string the language translates
/// differently -- and checks the layout runs the way that language reads.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/account/account_repository.dart';
import 'package:nebula_mobile/core/storage/locale_store.dart';
import 'package:nebula_mobile/core/storage/storage_providers.dart';
import 'package:nebula_mobile/features/account/account_screen.dart';
import 'package:nebula_mobile/features/account_request/account_request_screen.dart';
import 'package:nebula_mobile/features/activation/activation_screen.dart';
import 'package:nebula_mobile/features/auth/sign_in_screen.dart';
import 'package:nebula_mobile/features/devices/devices_screen.dart';
import 'package:nebula_mobile/features/password_reset/password_reset_confirm_screen.dart';
import 'package:nebula_mobile/features/password_reset/password_reset_request_screen.dart';
import 'package:nebula_mobile/features/settings/advanced_settings_screen.dart';
import 'package:nebula_mobile/features/settings/settings_screen.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/account/fake_account_repository.dart';
import '../support/localised_app.dart';

/// English strings that [language] translates differently.
///
/// Identical pairs are excluded: a brand, a technical token such as `{ms} ms`,
/// or a word German and English happen to share ("Server", "Status") is
/// deliberately the same, and finding it on that screen is correct.
/// Placeholder messages are excluded because they never render as written.
Map<String, String> _englishOnlyCopy(String language) {
  Map<String, dynamic> read(String name) =>
      jsonDecode(File('lib/l10n/$name').readAsStringSync())
          as Map<String, dynamic>;
  final Map<String, dynamic> english = read('app_en.arb');
  final Map<String, dynamic> translated = read('app_$language.arb');
  final Map<String, String> copy = <String, String>{};
  for (final MapEntry<String, dynamic> entry in english.entries) {
    if (entry.key.startsWith('@')) {
      continue;
    }
    final String value = entry.value as String;
    if (value.contains('{') || value == translated[entry.key]) {
      continue;
    }
    copy[value] = entry.key;
  }
  return copy;
}

/// The languages that read right to left.
const Set<String> _rightToLeft = <String>{'fa', 'ar'};

FakeAccountRepository _account() {
  return FakeAccountRepository()
    ..devices = <AccountDevice>[
      AccountDevice(
        id: 'device-this',
        name: 'Pixel 8',
        platform: 'android',
        state: 'active',
        clientVersion: '0.1.6',
        registeredAt: DateTime.utc(2026, 9, 2, 10),
        isCurrent: true,
        serverCodes: const <String>['de-fra-1'],
      ),
      AccountDevice(
        id: 'device-other',
        name: 'Windows desktop',
        platform: 'windows',
        state: 'active',
        clientVersion: '0.1.6',
        registeredAt: DateTime.utc(2026, 9, 2, 10),
        isCurrent: false,
        serverCodes: const <String>['nl-ams-1'],
      ),
    ]
    ..account = AccountSummary(
      email: 'owner@example.org',
      username: 'owner',
      state: 'active',
      deviceLimit: 5,
      devicesInUse: 2,
      usedBytes: 0,
    );
}

Future<void> _pump(WidgetTester tester, Widget screen, Locale locale) async {
  SharedPreferences.setMockInitialValues(<String, Object>{});
  final SharedPreferences preferences = await SharedPreferences.getInstance();
  await tester.pumpWidget(
    ProviderScope(
      overrides: <Override>[
        sharedPreferencesProvider.overrideWithValue(preferences),
        localeStoreProvider.overrideWithValue(InMemoryLocaleStore()),
        accountRepositoryProvider.overrideWithValue(_account()),
      ],
      child: localisedApp(screen, locale: locale),
    ),
  );
  await tester.pumpAndSettle();
}

/// Every string drawn on screen, including field hints and labels, which
/// live in InputDecoration rather than in a Text widget.
List<String> _visibleText(WidgetTester tester) {
  final List<String> seen = <String>[];
  for (final Widget widget in tester.allWidgets) {
    if (widget is Text && widget.data != null) {
      seen.add(widget.data!);
    } else if (widget is RichText) {
      seen.add(widget.text.toPlainText());
    } else if (widget is InputDecorator) {
      final InputDecoration decoration = widget.decoration;
      seen.addAll(
        <String?>[
          decoration.hintText,
          decoration.labelText,
          decoration.errorText,
        ].whereType<String>(),
      );
    }
  }
  return seen;
}

void main() {
  final List<String> languages = <String>[
    for (final Locale locale in AppText.supportedLocales)
      if (locale.languageCode != 'en') locale.languageCode,
  ];

  test('the check has languages, and English copy to look for in each', () {
    // Guards the guard: no languages, or an empty map, would pass everything.
    expect(languages.length, greaterThanOrEqualTo(9));
    for (final String language in languages) {
      expect(
        _englishOnlyCopy(language).length,
        greaterThan(150),
        reason: language,
      );
    }
  });

  final Map<String, Widget> screens = <String, Widget>{
    'sign in': const SignInScreen(),
    'request access': const AccountRequestScreen(),
    'activation': const ActivationScreen(),
    'password reset request': const PasswordResetRequestScreen(),
    'password reset confirm': const PasswordResetConfirmScreen(),
    'devices': const DevicesScreen(),
    'account': const AccountScreen(),
    'settings': const SettingsScreen(),
    'advanced settings': const AdvancedSettingsScreen(),
  };

  for (final String language in languages) {
    final Map<String, String> english = _englishOnlyCopy(language);
    for (final MapEntry<String, Widget> screen in screens.entries) {
      testWidgets('$language: ${screen.key} shows no English copy', (
        WidgetTester tester,
      ) async {
        await _pump(tester, screen.value, Locale(language));

        // A set: a Text and the RichText it builds carry the same string.
        final Set<String> leaked = <String>{
          for (final String text in _visibleText(tester))
            if (english.containsKey(text)) '"$text" (${english[text]})',
        };
        expect(
          leaked,
          isEmpty,
          reason:
              'these are still English on the $language ${screen.key} '
              'screen; read them through AppText',
        );
        expect(
          Directionality.of(
            tester.element(find.byType(screen.value.runtimeType)),
          ),
          _rightToLeft.contains(language)
              ? TextDirection.rtl
              : TextDirection.ltr,
        );
      });
    }
  }
}
