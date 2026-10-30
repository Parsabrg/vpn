import 'package:flutter/foundation.dart';

/// The address a build may carry, for builds that are not paired.
///
/// One generic build serves every installation: it has no address and is
/// paired on first launch (see `core/pairing/pairing.dart`). A build may still
/// carry one with `--dart-define=API_BASE_URL=https://...` -- an operator's
/// own branded build -- and debug builds default to the Android emulator's
/// alias for the host (`10.0.2.2`), where this repo's `compose.yaml`
/// publishes the API.
abstract final class ApiConfig {
  static const String _developmentBaseUrl = 'http://10.0.2.2:8000';

  static const String _configured = String.fromEnvironment('API_BASE_URL');

  /// The build's own address, or `null` for a generic build to be paired.
  static String? get presetBaseUrl =>
      resolve(configured: _configured, isRelease: kReleaseMode);

  /// The rule above, with `kReleaseMode` passed in.
  ///
  /// A release build with no address used to throw here, because the only
  /// alternative was a plaintext development address. With pairing, having
  /// none is the normal case for a release. A configured plaintext address
  /// still fails loudly: it would send credentials in the clear, and a build
  /// flag is far too quiet a thing for that to hinge on.
  ///
  /// Tests run in debug mode, so a guard reading `kReleaseMode` directly
  /// would have exactly one untestable branch -- the one that matters.
  @visibleForTesting
  static String? resolve({
    required String configured,
    required bool isRelease,
  }) {
    if (configured.isEmpty) {
      return isRelease ? null : _developmentBaseUrl;
    }
    if (isRelease && !configured.startsWith('https://')) {
      throw StateError(
        'API_BASE_URL must be https:// in a release build, got '
        '"$configured". Credentials and session tokens travel over this '
        'connection.',
      );
    }
    return configured;
  }

  static const String _configuredBackup = String.fromEnvironment(
    'API_BACKUP_URL',
  );

  /// Other addresses of the same API (a CDN, a web-host front), in the order
  /// to try them when [baseUrl] cannot be reached (see `route_fallback.dart`).
  /// Comma-separated; empty means none. Built in, not only learned from the
  /// server, because learning needs a call that gets through -- on a
  /// throttled address the first one may never do. Held to the same https
  /// rule, since the same credentials travel over them.
  static List<String> get backupBaseUrls => <String>[
    for (final String entry in _configuredBackup.split(','))
      if (entry.trim().isNotEmpty)
        resolve(configured: entry.trim(), isRelease: kReleaseMode)!,
  ];

  static const Duration connectTimeout = Duration(seconds: 10);
  static const Duration receiveTimeout = Duration(seconds: 10);
}
