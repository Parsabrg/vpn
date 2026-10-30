import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/licenses/bundled_licenses.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'the bundled engines are on the licenses page, with their notices',
    () async {
      registerBundledLicenses();
      final Map<String, String> found = <String, String>{};
      await for (final LicenseEntry entry in LicenseRegistry.licenses) {
        final String text = entry.paragraphs.map((p) => p.text).join('\n');
        for (final String package in entry.packages) {
          found[package] = text;
        }
      }
      expect(found['Nebula VPN'], contains('GNU GENERAL PUBLIC LICENSE'));
      expect(found['Xray-core'], contains('Mozilla Public License'));
      expect(found['Hysteria'], contains('Permission is hereby granted'));
      expect(found['hev-socks5-tunnel'], isNotNull);
      expect(found['Wintun'], contains('Prebuilt Binaries License'));
      expect(found['v2fly geoip'], contains('CC BY-SA 4.0'));
    },
  );
}
