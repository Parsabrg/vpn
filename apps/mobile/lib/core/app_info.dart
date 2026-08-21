import 'dart:io';

import 'auth/auth_repository.dart';

/// Kept in manual sync with `pubspec.yaml`'s `version:` field. No
/// `package_info_plus` dependency this phase -- see Phase 1.7a's plan doc
/// for the dependency-discipline rationale.
const String kClientVersion = '0.1.0';

/// `dart:io`'s `Platform.operatingSystem` is sufficient to answer this
/// API's `platform` enum without a plugin -- this app has no other target
/// platforms in Phase 1.
DevicePlatform get currentDevicePlatform =>
    Platform.isAndroid ? DevicePlatform.android : DevicePlatform.windows;

/// Honest placeholder device name: no OS API exposes a human-readable
/// device name from `dart:io` alone, and this project's ethos is to never
/// fake specific-looking data. A real device name is reasonable
/// `device_info_plus`/1.8 scope once native platform code exists anyway.
String get currentDeviceName => '${Platform.operatingSystem} device';
