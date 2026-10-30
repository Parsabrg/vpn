import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/network/api_config.dart';

/// The default base URL is a plain-HTTP emulator address, and it used to apply
/// to every build -- so a release built without `--dart-define=API_BASE_URL`
/// shipped pointing at cleartext, with nothing anywhere to say so. For an app
/// whose users are avoiding network surveillance, that is the worst available
/// failure, and it hinged on remembering one build flag.
void main() {
  group('release builds', () {
    test('never fall back to the plaintext development address', () {
      // No address at all is the generic build: it is paired on first launch.
      expect(ApiConfig.resolve(configured: '', isRelease: true), isNull);
    });

    test('refuse a plaintext URL even when one was configured', () {
      expect(
        () => ApiConfig.resolve(
          configured: 'http://api.example.org',
          isRelease: true,
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('refuse a scheme that merely contains https', () {
      expect(
        () => ApiConfig.resolve(
          configured: 'http://https.example.org',
          isRelease: true,
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('accept an https URL', () {
      expect(
        ApiConfig.resolve(
          configured: 'https://api.example.org',
          isRelease: true,
        ),
        'https://api.example.org',
      );
    });
  });

  group('debug builds', () {
    test('keep the emulator fallback, which is what it is for', () {
      expect(
        ApiConfig.resolve(configured: '', isRelease: false),
        'http://10.0.2.2:8000',
      );
    });

    test('allow a plaintext URL against a local API', () {
      expect(
        ApiConfig.resolve(
          configured: 'http://127.0.0.1:8000',
          isRelease: false,
        ),
        'http://127.0.0.1:8000',
      );
    });
  });
}
