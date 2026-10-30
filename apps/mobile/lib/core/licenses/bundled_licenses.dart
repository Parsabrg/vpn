import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// What ships beside the app's Dart code, under licenses that want their
/// notices carried with every copy (THIRD_PARTY_NOTICES.md). Flutter collects
/// the Dart packages' licenses by itself; these it cannot see.
const List<(List<String>, String)> _bundled = <(List<String>, String)>[
  (<String>['Nebula VPN'], 'nebula-gpl-3.0.txt'),
  (<String>['Xray-core'], 'xray-core.txt'),
  (<String>['AndroidLibXrayLite'], 'androidlibxraylite.txt'),
  (<String>['Hysteria'], 'hysteria.txt'),
  (<String>['hev-socks5-tunnel'], 'hev-socks5-tunnel.txt'),
  (<String>['WireGuard for Android'], 'wireguard-android.txt'),
  (<String>['wireguard-go'], 'wireguard-go.txt'),
  (<String>['Wintun'], 'wintun.txt'),
  (<String>['v2fly geoip'], 'geoip.txt'),
  (<String>['v2fly domain-list-community'], 'domain-list-community.txt'),
];

/// Adds them to Flutter's licenses page (Settings › Open-source licenses).
void registerBundledLicenses() {
  LicenseRegistry.addLicense(() async* {
    for (final (List<String> packages, String file) in _bundled) {
      yield LicenseEntryWithLineBreaks(
        packages,
        await rootBundle.loadString('assets/licenses/$file'),
      );
    }
  });
}
