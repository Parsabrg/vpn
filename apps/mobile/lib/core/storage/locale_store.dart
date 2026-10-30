import 'package:shared_preferences/shared_preferences.dart';

/// Which language the app is shown in.
///
/// Null means follow the device, which is the default and is right for almost
/// everyone: a phone set to Persian should open a Persian app without anybody
/// choosing anything.
///
/// The override exists because that assumption breaks in both directions.
/// Plenty of people in Iran run their phone in English and would rather read
/// Persian here, and plenty run it in Persian and would rather read the
/// English words they already recognise from other VPN clients.
abstract interface class LocaleStore {
  String? readLanguageCode();
  Future<void> writeLanguageCode(String? languageCode);
}

class SharedPreferencesLocaleStore implements LocaleStore {
  SharedPreferencesLocaleStore(this._preferences);

  static const String _key = 'nebula.language_code';

  final SharedPreferences _preferences;

  @override
  String? readLanguageCode() => _preferences.getString(_key);

  @override
  Future<void> writeLanguageCode(String? languageCode) {
    // Clearing is a real choice: going back to "follow the device" has to be
    // remembered, or the next launch restores a language just undone.
    if (languageCode == null) {
      return _preferences.remove(_key);
    }
    return _preferences.setString(_key, languageCode);
  }
}

class InMemoryLocaleStore implements LocaleStore {
  String? _languageCode;

  @override
  String? readLanguageCode() => _languageCode;

  @override
  Future<void> writeLanguageCode(String? languageCode) async {
    _languageCode = languageCode;
  }
}
