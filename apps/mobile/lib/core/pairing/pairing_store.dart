import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'pairing.dart';

/// Where the pairing is kept. Secure storage rather than preferences: it
/// holds the CA this app trusts for its API, and replacing that is how
/// someone with access to the device's files would redirect it.
abstract interface class PairingStore {
  Future<Pairing?> read();
  Future<void> write(Pairing pairing);
  Future<void> clear();
}

class FlutterSecurePairingStore implements PairingStore {
  FlutterSecurePairingStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _key = 'nebula.pairing';

  final FlutterSecureStorage _storage;

  @override
  Future<Pairing?> read() async {
    final String? stored = await _storage.read(key: _key);
    if (stored == null) {
      return null;
    }
    try {
      return Pairing.fromJson(jsonDecode(stored) as Map<String, Object?>);
    } on Object {
      // Written by a build whose shape has since changed, or damaged: the
      // app asks to be paired again rather than guessing at a server.
      return null;
    }
  }

  @override
  Future<void> write(Pairing pairing) =>
      _storage.write(key: _key, value: jsonEncode(pairing.toJson()));

  @override
  Future<void> clear() => _storage.delete(key: _key);
}

class InMemoryPairingStore implements PairingStore {
  InMemoryPairingStore([this._pairing]);

  Pairing? _pairing;

  @override
  Future<Pairing?> read() async => _pairing;

  @override
  Future<void> write(Pairing pairing) async {
    _pairing = pairing;
  }

  @override
  Future<void> clear() async {
    _pairing = null;
  }
}
