import 'dart:ui';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/app_localizations.dart';
import '../storage/storage_providers.dart';

/// The languages this app is written in.
///
/// Listed here rather than read from the generated localisations so the
/// picker can name each one *in its own language*: somebody who cannot read
/// the current language still has to be able to find their way out of it.
enum AppLanguage {
  // English first, then Latin scripts alphabetically by their own names,
  // then the rest. The order is only what the picker shows.
  english('en', 'English'),
  german('de', 'Deutsch'),
  spanish('es', 'Español'),
  french('fr', 'Français'),
  dutch('nl', 'Nederlands'),
  turkish('tr', 'Türkçe'),
  russian('ru', 'Русский'),
  arabic('ar', 'العربية'),
  persian('fa', 'فارسی'),
  chinese('zh', '中文（简体）');

  const AppLanguage(this.code, this.endonym);

  /// The language tag, matching the ARB file it comes from.
  final String code;

  /// What speakers of the language call it. Never translated -- a list that
  /// said "Persian" in English and "انگلیسی" in Persian would be unreadable
  /// to exactly the person trying to escape the wrong choice.
  final String endonym;

  static AppLanguage? forCode(String? code) {
    for (final AppLanguage language in AppLanguage.values) {
      if (language.code == code) {
        return language;
      }
    }
    return null;
  }
}

/// The chosen language, or null to follow the device.
class LocaleController extends Notifier<AppLanguage?> {
  @override
  AppLanguage? build() {
    return AppLanguage.forCode(
      ref.watch(localeStoreProvider).readLanguageCode(),
    );
  }

  Future<void> choose(AppLanguage? language) async {
    // State first, so the screen turns over under the finger rather than
    // after a disk round trip -- the same trade every other setting makes.
    state = language;
    await ref.read(localeStoreProvider).writeLanguageCode(language?.code);
  }
}

final NotifierProvider<LocaleController, AppLanguage?>
localeControllerProvider = NotifierProvider<LocaleController, AppLanguage?>(
  LocaleController.new,
);

/// What MaterialApp is given.
///
/// Null hands the decision to [resolveAppLocale], which matches the device's
/// languages against the supported list and falls back to English. Returning
/// a locale unconditionally would quietly ignore the phone's own setting.
final Provider<Locale?> appLocaleProvider = Provider<Locale?>((Ref ref) {
  final AppLanguage? chosen = ref.watch(localeControllerProvider);
  return chosen == null ? null : Locale(chosen.code);
});

/// The strings for whichever language the app is showing, for code that has
/// no `BuildContext` to ask.
///
/// Controllers turn a caught error into a sentence and keep the sentence in
/// their state, so they need the language at the moment it happens. Resolved
/// the way `MaterialApp` resolves it -- the language chosen in Settings, or
/// else the device's -- and falling back to English for any device language
/// the app does not ship, exactly as the widgets do. A message written just
/// before somebody switches language stays in the old one until the next
/// attempt, which is the only cost of keeping sentences in state.
final Provider<AppText> appTextProvider = Provider<AppText>((Ref ref) {
  final Locale? chosen = ref.watch(appLocaleProvider);
  return lookupAppText(
    resolveAppLocale(
      chosen == null ? PlatformDispatcher.instance.locales : <Locale>[chosen],
      AppText.supportedLocales,
    ),
  );
});

/// The language the app shows: the first of [preferred] it ships, by
/// language alone, or else English.
///
/// Explicit rather than Flutter's default resolution, which falls back to
/// the *first* supported locale. The generated list is alphabetical, so with
/// Arabic in it that default would open the app in Arabic on every phone set
/// to a language it does not ship.
Locale resolveAppLocale(List<Locale>? preferred, Iterable<Locale> supported) {
  for (final Locale locale in preferred ?? const <Locale>[]) {
    for (final Locale candidate in supported) {
      if (candidate.languageCode == locale.languageCode) {
        return candidate;
      }
    }
  }
  return const Locale('en');
}
