/// A MaterialApp for widget tests, with the localisations wired.
///
/// Every screen now reads its copy through `AppText.of(context)`, which throws
/// when the delegates are absent -- so a test that builds a bare MaterialApp
/// fails with a stack trace from the generated localisations rather than
/// anything about the screen it meant to exercise.
///
/// Shared rather than repeated in each test file so adding a locale, or
/// changing how the app resolves one, is a single edit in the tests as well as
/// in the app.
library;

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:nebula_mobile/core/theme/nebula_theme.dart';
import 'package:nebula_mobile/l10n/app_localizations.dart';

/// Wraps [home] the way `NebulaApp` wraps the router.
///
/// [locale] defaults to English. Pass `Locale('fa')` to render a screen the
/// way somebody reading Persian sees it, right-to-left included -- which is
/// the only way a layout that breaks under RTL shows up in a test.
Widget localisedApp(Widget home, {Locale locale = const Locale('en')}) {
  return MaterialApp(
    theme: NebulaTheme.dark(),
    locale: locale,
    supportedLocales: AppText.supportedLocales,
    localizationsDelegates: const <LocalizationsDelegate<Object>>[
      AppText.delegate,
      GlobalMaterialLocalizations.delegate,
      GlobalWidgetsLocalizations.delegate,
      GlobalCupertinoLocalizations.delegate,
    ],
    home: home,
  );
}
