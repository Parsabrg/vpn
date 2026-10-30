import 'package:shared_preferences/shared_preferences.dart';

/// When Android last brought a saved tunnel back without this app.
///
/// After a phone restart or an app update, `RestartReceiver` restarts the
/// tunnel natively -- a new session, with counters from zero -- and nothing in
/// Dart sees it happen. It notes the moment here so a later run can tell a
/// tunnel that has been up all along from one that started again underneath
/// the record.
abstract interface class TunnelRestoreStore {
  Future<DateTime?> lastRestoredAt();
}

/// Reads what `RestartReceiver` writes into Flutter's own preferences file.
///
/// Reloaded first: the value is written by native code, possibly after this
/// process loaded the file, and the plugin caches what it loaded.
class SharedPreferencesTunnelRestoreStore implements TunnelRestoreStore {
  SharedPreferencesTunnelRestoreStore(this._preferences);

  /// Without the `flutter.` prefix the native side adds.
  static const String key = 'nebula.tunnel_restored_at';

  final SharedPreferences _preferences;

  @override
  Future<DateTime?> lastRestoredAt() async {
    await _preferences.reload();
    final int? millis = _preferences.getInt(key);
    return millis == null ? null : DateTime.fromMillisecondsSinceEpoch(millis);
  }
}

class InMemoryTunnelRestoreStore implements TunnelRestoreStore {
  DateTime? restoredAt;

  @override
  Future<DateTime?> lastRestoredAt() async => restoredAt;
}
