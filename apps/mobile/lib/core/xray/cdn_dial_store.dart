import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../storage/storage_providers.dart';
import 'xray_config.dart';

/// The Cloudflare dial that last carried traffic, tried first next time.
class LastCdnDial {
  LastCdnDial(this._preferences);

  final SharedPreferences _preferences;

  static const String _key = 'nebula.cdn_dial';

  CdnDial? read() {
    final String? name = _preferences.getString(_key);
    for (final CdnDial dial in CdnDial.values) {
      if (dial.name == name) {
        return dial;
      }
    }
    return null;
  }

  Future<void> write(CdnDial dial) => _preferences.setString(_key, dial.name);
}

final lastCdnDialProvider = Provider<LastCdnDial>(
  (Ref ref) => LastCdnDial(ref.watch(sharedPreferencesProvider)),
);

/// Whether this device has a global IPv6 address (2000::/3) outside a VPN's
/// own interface, so an IPv6 dial can go anywhere at all.
final deviceHasIpv6Provider = Provider<Future<bool> Function()>(
  (Ref ref) => () async {
    try {
      final List<NetworkInterface> interfaces = await NetworkInterface.list(
        type: InternetAddressType.IPv6,
      );
      return interfaces.any(
        (NetworkInterface i) =>
            !i.name.startsWith('tun') &&
            i.name != 'Nebula' &&
            i.addresses.any(
              (InternetAddress a) => (a.rawAddress[0] & 0xE0) == 0x20,
            ),
      );
    } on Object {
      return false;
    }
  },
);
