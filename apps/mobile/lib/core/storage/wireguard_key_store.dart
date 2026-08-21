import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Narrow interface over secure at-rest storage for this device's WireGuard
/// private key -- the same Keystore/DPAPI-backed store as
/// [SecureTokenStore], kept as its own class so a caller can never
/// accidentally read/write the wrong secret.
abstract interface class WireGuardKeyStore {
  Future<String?> readPrivateKey();
  Future<void> writePrivateKey(String privateKeyBase64);
  Future<void> clear();
}

class FlutterWireGuardKeyStore implements WireGuardKeyStore {
  FlutterWireGuardKeyStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _privateKeyKey = 'nebula.wireguard_private_key';

  final FlutterSecureStorage _storage;

  @override
  Future<String?> readPrivateKey() => _storage.read(key: _privateKeyKey);

  @override
  Future<void> writePrivateKey(String privateKeyBase64) =>
      _storage.write(key: _privateKeyKey, value: privateKeyBase64);

  @override
  Future<void> clear() => _storage.delete(key: _privateKeyKey);
}

/// In-memory fake for tests -- no platform channel required.
class InMemoryWireGuardKeyStore implements WireGuardKeyStore {
  String? _privateKey;

  @override
  Future<String?> readPrivateKey() async => _privateKey;

  @override
  Future<void> writePrivateKey(String privateKeyBase64) async {
    _privateKey = privateKeyBase64;
  }

  @override
  Future<void> clear() async {
    _privateKey = null;
  }
}
