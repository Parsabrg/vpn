import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Narrow, platform-independent interface over secure at-rest storage.
///
/// Only the refresh token is ever persisted here. The short-lived access
/// token stays in memory (see `core/auth/auth_notifier.dart`) -- a cold
/// start always refreshes anyway, so persisting it would add at-rest secret
/// surface for no benefit.
///
/// Kept as an interface (not the raw `FlutterSecureStorage` API) so tests
/// can substitute [InMemorySecureTokenStore]: the real implementation hits
/// platform channels that do not exist in the headless `flutter test`
/// harness this project's CI relies on.
abstract interface class SecureTokenStore {
  Future<String?> readRefreshToken();
  Future<void> writeRefreshToken(String token);
  Future<void> clear();
}

class FlutterSecureTokenStore implements SecureTokenStore {
  FlutterSecureTokenStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _refreshTokenKey = 'nebula.refresh_token';

  final FlutterSecureStorage _storage;

  @override
  Future<String?> readRefreshToken() => _storage.read(key: _refreshTokenKey);

  @override
  Future<void> writeRefreshToken(String token) =>
      _storage.write(key: _refreshTokenKey, value: token);

  @override
  Future<void> clear() => _storage.delete(key: _refreshTokenKey);
}

/// In-memory fake for tests -- no platform channel required.
class InMemorySecureTokenStore implements SecureTokenStore {
  String? _refreshToken;

  @override
  Future<String?> readRefreshToken() async => _refreshToken;

  @override
  Future<void> writeRefreshToken(String token) async {
    _refreshToken = token;
  }

  @override
  Future<void> clear() async {
    _refreshToken = null;
  }
}
