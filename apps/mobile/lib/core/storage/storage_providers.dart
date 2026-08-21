import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'device_id_store.dart';
import 'secure_token_store.dart';
import 'theme_preference_store.dart';

/// Must be overridden in `main()` with the real instance after awaiting
/// `SharedPreferences.getInstance()` -- reading it before that override is
/// installed is a programming error, not a recoverable runtime state.
final sharedPreferencesProvider = Provider<SharedPreferences>((Ref ref) {
  throw UnimplementedError(
    'sharedPreferencesProvider must be overridden in main() with the '
    'result of SharedPreferences.getInstance().',
  );
});

final secureTokenStoreProvider = Provider<SecureTokenStore>((Ref ref) {
  return FlutterSecureTokenStore();
});

final deviceIdStoreProvider = Provider<DeviceIdStore>((Ref ref) {
  return SharedPreferencesDeviceIdStore(ref.watch(sharedPreferencesProvider));
});

final themePreferenceStoreProvider = Provider<ThemePreferenceStore>((
  Ref ref,
) {
  return SharedPreferencesThemeStore(ref.watch(sharedPreferencesProvider));
});
