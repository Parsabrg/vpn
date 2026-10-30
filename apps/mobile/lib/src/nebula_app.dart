import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/routing/app_router.dart';
import '../core/settings/locale_controller.dart';
import '../core/theme/nebula_theme.dart';
import '../core/theme/theme_mode_controller.dart';
import '../l10n/app_localizations.dart';

class NebulaApp extends ConsumerWidget {
  const NebulaApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final ThemeMode themeMode = ref.watch(themeModeProvider);

    return MaterialApp.router(
      debugShowCheckedModeBanner: false,
      // Not localised. This is the task-switcher label and the name on the
      // launcher icon, and somebody looking for the app looks for this word
      // whatever language they read.
      title: 'Nebula VPN',
      theme: NebulaTheme.light(),
      darkTheme: NebulaTheme.dark(),
      themeMode: themeMode,
      // Null follows the device, which is what almost everybody wants. Only a
      // deliberate choice in Settings overrides it.
      locale: ref.watch(appLocaleProvider),
      supportedLocales: AppText.supportedLocales,
      // English for a device language the app does not ship. Flutter's own
      // fallback is the first supported locale, which is Arabic.
      localeListResolutionCallback:
          (List<Locale>? preferred, Iterable<Locale> supported) =>
              resolveAppLocale(preferred, supported),
      // The Material and Widgets delegates are what give each language its
      // own date formats and text selection handles, and Persian and Arabic
      // -- the one that shows immediately -- a right-to-left layout.
      localizationsDelegates: const <LocalizationsDelegate<Object>>[
        AppText.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      routerConfig: ref.watch(routerProvider),
    );
  }
}
