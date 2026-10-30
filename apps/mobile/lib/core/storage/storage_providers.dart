import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'advanced_settings_store.dart';
import 'connection_record_store.dart';
import 'device_id_store.dart';
import 'locale_store.dart';
import 'protection_preference_store.dart';
import 'protocol_history_store.dart';
import 'secure_token_store.dart';
import 'selection_store.dart';
import 'split_tunnel_store.dart';
import 'theme_preference_store.dart';
import 'tunnel_restore_store.dart';
import 'wireguard_key_store.dart';
import 'xray_credential_store.dart';

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

final xrayCredentialStoreProvider = Provider<XrayCredentialStore>((Ref ref) {
  return FlutterSecureXrayCredentialStore();
});

final deviceIdStoreProvider = Provider<DeviceIdStore>((Ref ref) {
  return SharedPreferencesDeviceIdStore(ref.watch(sharedPreferencesProvider));
});

final protocolHistoryStoreProvider = Provider<ProtocolHistoryStore>((Ref ref) {
  return SharedPreferencesProtocolHistoryStore(
    ref.watch(sharedPreferencesProvider),
  );
});

final selectionStoreProvider = Provider<SelectionStore>((Ref ref) {
  return SharedPreferencesSelectionStore(ref.watch(sharedPreferencesProvider));
});

final themePreferenceStoreProvider = Provider<ThemePreferenceStore>((Ref ref) {
  return SharedPreferencesThemeStore(ref.watch(sharedPreferencesProvider));
});

final protectionPreferenceStoreProvider = Provider<ProtectionPreferenceStore>((
  Ref ref,
) {
  return SharedPreferencesProtectionStore(ref.watch(sharedPreferencesProvider));
});

final connectionRecordStoreProvider = Provider<ConnectionRecordStore>((
  Ref ref,
) {
  return SecureConnectionRecordStore();
});

final tunnelRestoreStoreProvider = Provider<TunnelRestoreStore>((Ref ref) {
  return SharedPreferencesTunnelRestoreStore(
    ref.watch(sharedPreferencesProvider),
  );
});

final wireGuardKeyStoreProvider = Provider<WireGuardKeyStore>((Ref ref) {
  return FlutterWireGuardKeyStore();
});

final splitTunnelStoreProvider = Provider<SplitTunnelStore>((Ref ref) {
  return SharedPreferencesSplitTunnelStore(
    ref.watch(sharedPreferencesProvider),
  );
});

final advancedSettingsStoreProvider = Provider<AdvancedSettingsStore>((
  Ref ref,
) {
  return SharedPreferencesAdvancedSettingsStore(
    ref.watch(sharedPreferencesProvider),
  );
});

final localeStoreProvider = Provider<LocaleStore>((Ref ref) {
  return SharedPreferencesLocaleStore(ref.watch(sharedPreferencesProvider));
});
