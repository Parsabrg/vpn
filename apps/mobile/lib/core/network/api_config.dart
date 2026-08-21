/// Base URL the app talks to, injected at build time so no environment
/// switching logic needs to live in the app itself.
///
/// `10.0.2.2` is the Android emulator's alias for the host machine's
/// `localhost`, matching how this repo's `compose.yaml` exposes the API
/// locally. Override with `--dart-define=API_BASE_URL=https://...` for
/// staging/production builds.
abstract final class ApiConfig {
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:8000',
  );

  static const Duration connectTimeout = Duration(seconds: 10);
  static const Duration receiveTimeout = Duration(seconds: 10);
}
