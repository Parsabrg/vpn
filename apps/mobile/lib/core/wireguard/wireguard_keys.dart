import 'dart:convert';

import 'package:cryptography/cryptography.dart';

/// A WireGuard identity: a Curve25519 key pair, base64-encoded the same way
/// `wg genkey`/`wg pubkey` do. Only [publicKeyBase64] is ever sent to the
/// API -- the private key never leaves the device.
class WireGuardKeyPair {
  const WireGuardKeyPair({
    required this.publicKeyBase64,
    required this.privateKeyBase64,
  });

  final String publicKeyBase64;
  final String privateKeyBase64;
}

/// Pure-Dart X25519 key generation (`package:cryptography`'s Dart
/// implementation, no native platform code) -- consistent with this app
/// staying Dart-only until Android/Windows runner projects exist.
class WireGuardKeyGenerator {
  const WireGuardKeyGenerator();

  Future<WireGuardKeyPair> generate() async {
    final SimpleKeyPair keyPair = await X25519().newKeyPair();
    return _fromKeyPair(keyPair);
  }

  /// Deterministically reconstructs both halves of a previously generated
  /// pair from its stored private key -- X25519 clamping is idempotent, so
  /// re-deriving from an already-clamped seed reproduces the same public
  /// key every time.
  Future<WireGuardKeyPair> fromStoredPrivateKey(String privateKeyBase64) async {
    final List<int> seed = base64Decode(privateKeyBase64);
    final SimpleKeyPair keyPair = await X25519().newKeyPairFromSeed(seed);
    return _fromKeyPair(keyPair);
  }

  Future<WireGuardKeyPair> _fromKeyPair(SimpleKeyPair keyPair) async {
    final List<int> privateKeyBytes = await keyPair.extractPrivateKeyBytes();
    final SimplePublicKey publicKey = await keyPair.extractPublicKey();
    return WireGuardKeyPair(
      publicKeyBase64: base64Encode(publicKey.bytes),
      privateKeyBase64: base64Encode(privateKeyBytes),
    );
  }
}
