import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/xray/windows_vpn_supervisor.dart';

void main() {
  test('never wraps ConvertFrom-Json directly in @()', () {
    // Windows PowerShell 5.1 emits a JSON array as one object, so this
    // idiom yields a one-item list holding the whole array. It made every
    // Windows connect fail at "validating the VPN configuration".
    expect(windowsVpnSupervisorScript, isNot(contains('@(ConvertFrom-Json')));
  });

  test(
    'the parsing idiom it uses yields the elements under PowerShell 5.1',
    () async {
      final ProcessResult result = await Process.run('powershell.exe', <String>[
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        r'''$parsed = ConvertFrom-Json -InputObject '["1.1.1.1","8.8.8.8"]'; $r = @($parsed); "$($r.Count) $($r[0] -is [string])"''',
      ]);
      expect((result.stdout as String).trim(), '2 True');
    },
    skip: !Platform.isWindows,
  );
}
