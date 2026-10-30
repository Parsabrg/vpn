import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// An id for this machine that survives uninstalling the app, sent at
/// sign-in so a reinstall gets its old device back instead of taking a new
/// slot of the account's device limit.
///
/// Only a SHA-256 of the platform's id leaves the device: Android's
/// ANDROID_ID (per signing key and user, kept across reinstalls), Windows'
/// MachineGuid, Linux's machine-id. Null when the platform will not give one;
/// sign-in then works as before.
final hardwareIdProvider = Provider<Future<String?> Function()>(
  (Ref ref) => readHardwareId,
);

Future<String?> readHardwareId() async {
  try {
    final String? raw = await _platformId();
    if (raw == null || raw.trim().isEmpty) {
      return null;
    }
    final Hash hash = await Sha256().hash(
      utf8.encode('nebula.hardware:${raw.trim()}'),
    );
    return hash.bytes
        .map((int byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
  } catch (_) {
    return null;
  }
}

Future<String?> _platformId() async {
  if (Platform.isAndroid) {
    return const MethodChannel(
      'org.nebulavpn/wireguard_tunnel',
    ).invokeMethod<String>('hardwareId');
  }
  if (Platform.isWindows) {
    final ProcessResult result = await Process.run('reg', <String>[
      'query',
      r'HKLM\SOFTWARE\Microsoft\Cryptography',
      '/v',
      'MachineGuid',
    ]);
    final RegExpMatch? match = RegExp(
      r'MachineGuid\s+REG_SZ\s+(\S+)',
    ).firstMatch(result.stdout as String);
    return match?.group(1);
  }
  if (Platform.isLinux) {
    return File('/etc/machine-id').readAsString();
  }
  return null;
}
