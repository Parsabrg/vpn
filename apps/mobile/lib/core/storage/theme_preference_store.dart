import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Persists the user's theme-mode override. Not sensitive, so plain
/// (non-secure) local storage is appropriate -- the same store this app uses
/// for the non-secret `device_id` (see `device_id_store.dart`).
abstract interface class ThemePreferenceStore {
  ThemeMode read();
  Future<void> write(ThemeMode mode);
}

class SharedPreferencesThemeStore implements ThemePreferenceStore {
  SharedPreferencesThemeStore(this._preferences);

  static const String _key = 'nebula.theme_mode';

  final SharedPreferences _preferences;

  @override
  ThemeMode read() {
    final String? stored = _preferences.getString(_key);
    return ThemeMode.values.firstWhere(
      (ThemeMode mode) => mode.name == stored,
      orElse: () => ThemeMode.system,
    );
  }

  @override
  Future<void> write(ThemeMode mode) => _preferences.setString(_key, mode.name);
}

/// In-memory fake for tests.
class InMemoryThemeStore implements ThemePreferenceStore {
  ThemeMode _mode = ThemeMode.system;

  @override
  ThemeMode read() => _mode;

  @override
  Future<void> write(ThemeMode mode) async {
    _mode = mode;
  }
}
