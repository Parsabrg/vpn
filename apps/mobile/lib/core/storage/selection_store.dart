import 'package:shared_preferences/shared_preferences.dart';

/// Remembers which server and protocol were last chosen.
///
/// Not a credential and not state the server owns: it is what this person
/// picked last time, so the app opens where they left it instead of asking
/// the same two questions on every launch.
///
/// Read back defensively. A remembered choice is only a hint -- a server can
/// be withdrawn from an account and a profile can be disabled between one
/// launch and the next, so whatever comes back here has to be checked against
/// what the account can currently reach before it is used.
abstract interface class SelectionStore {
  String? readServerCode();
  String? readProfileCode();
  Future<void> writeServerCode(String? serverCode);
  Future<void> writeProfileCode(String? profileCode);
}

class SharedPreferencesSelectionStore implements SelectionStore {
  SharedPreferencesSelectionStore(this._preferences);

  static const String _serverKey = 'nebula.selected_server_code';
  static const String _profileKey = 'nebula.selected_profile_code';

  final SharedPreferences _preferences;

  @override
  String? readServerCode() => _preferences.getString(_serverKey);

  @override
  String? readProfileCode() => _preferences.getString(_profileKey);

  @override
  Future<void> writeServerCode(String? serverCode) {
    // Clearing is a real operation: deselecting has to be remembered too, or
    // the next launch restores a choice the person has just undone.
    if (serverCode == null) {
      return _preferences.remove(_serverKey);
    }
    return _preferences.setString(_serverKey, serverCode);
  }

  @override
  Future<void> writeProfileCode(String? profileCode) {
    if (profileCode == null) {
      return _preferences.remove(_profileKey);
    }
    return _preferences.setString(_profileKey, profileCode);
  }
}

/// In-memory fake for tests.
class InMemorySelectionStore implements SelectionStore {
  String? _serverCode;
  String? _profileCode;

  @override
  String? readServerCode() => _serverCode;

  @override
  String? readProfileCode() => _profileCode;

  @override
  Future<void> writeServerCode(String? serverCode) async {
    _serverCode = serverCode;
  }

  @override
  Future<void> writeProfileCode(String? profileCode) async {
    _profileCode = profileCode;
  }
}
