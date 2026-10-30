import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/wireguard/wireguard_keys.dart';

const String _publicKeyPattern = r'^[A-Za-z0-9+/]{43}=$';

void main() {
  group('WireGuardKeyGenerator', () {
    test(
      'generates a public key matching the API\'s expected format',
      () async {
        final WireGuardKeyPair pair = await const WireGuardKeyGenerator()
            .generate();

        expect(pair.publicKeyBase64.length, 44);
        expect(
          RegExp(_publicKeyPattern).hasMatch(pair.publicKeyBase64),
          isTrue,
          reason: 'Got: ${pair.publicKeyBase64}',
        );
      },
    );

    test('two generated pairs are not the same key', () async {
      const WireGuardKeyGenerator generator = WireGuardKeyGenerator();
      final WireGuardKeyPair first = await generator.generate();
      final WireGuardKeyPair second = await generator.generate();

      expect(first.publicKeyBase64, isNot(second.publicKeyBase64));
      expect(first.privateKeyBase64, isNot(second.privateKeyBase64));
    });

    test(
      'reconstructing from a stored private key reproduces the same public key',
      () async {
        const WireGuardKeyGenerator generator = WireGuardKeyGenerator();
        final WireGuardKeyPair original = await generator.generate();

        final WireGuardKeyPair reconstructed = await generator
            .fromStoredPrivateKey(original.privateKeyBase64);

        expect(reconstructed.publicKeyBase64, original.publicKeyBase64);
        expect(reconstructed.privateKeyBase64, original.privateKeyBase64);
      },
    );
  });
}
