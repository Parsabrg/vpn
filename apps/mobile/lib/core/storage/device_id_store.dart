import 'package:shared_preferences/shared_preferences.dart';

/// Persists the server-assigned `device_id` learned from `GET /v1/auth/me`.
///
/// Not a credential -- it is an opaque identifier the server itself uses to
/// scope sessions, so plain (non-secure) local storage is appropriate.
abstract interface class DeviceIdStore {
  String? read();
  Future<void> write(String deviceId);
}

class SharedPreferencesDeviceIdStore implements DeviceIdStore {
  SharedPreferencesDeviceIdStore(this._preferences);

  static const String _key = 'nebula.device_id';

  final SharedPreferences _preferences;

  @override
  String? read() => _preferences.getString(_key);

  @override
  Future<void> write(String deviceId) => _preferences.setString(_key, deviceId);
}

/// In-memory fake for tests.
class InMemoryDeviceIdStore implements DeviceIdStore {
  String? _deviceId;

  @override
  String? read() => _deviceId;

  @override
  Future<void> write(String deviceId) async {
    _deviceId = deviceId;
  }
}
