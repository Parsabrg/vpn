import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/wireguard/windows_wireguard_tunnel.dart';

void main() {
  // The client used to assume C:\Program Files\WireGuard, which is wrong on
  // any machine whose system drive or Program Files is elsewhere.
  test('finds WireGuard where Windows says Program Files is', () {
    final WindowsWireGuardTunnel tunnel = WindowsWireGuardTunnel(
      environment: const <String, String>{'ProgramFiles': r'D:\Apps'},
      exists: (String path) => path == r'D:\Apps\WireGuard\wireguard.exe',
    );

    expect(
      tunnel.findTool('wireguard.exe'),
      r'D:\Apps\WireGuard\wireguard.exe',
    );
  });

  test('an explicit directory wins', () {
    final WindowsWireGuardTunnel tunnel = WindowsWireGuardTunnel(
      environment: const <String, String>{
        'NEBULA_WIREGUARD_DIR': r'E:\Tools\wg\',
        'ProgramFiles': r'C:\Program Files',
      },
      exists: (String path) => true,
    );

    expect(tunnel.findTool('wg.exe'), r'E:\Tools\wg\wg.exe');
  });

  test('falls back to PATH', () {
    final WindowsWireGuardTunnel tunnel = WindowsWireGuardTunnel(
      environment: const <String, String>{'PATH': r'C:\Windows;F:\wg'},
      exists: (String path) => path == r'F:\wg\wg.exe',
    );

    expect(tunnel.findTool('wg.exe'), r'F:\wg\wg.exe');
  });

  // wireguard.exe does not elevate itself: run directly from the app it
  // failed with "Access is denied" and no UAC prompt, so WireGuard never
  // connected on Windows.
  test('asks for elevation once, and says when it is declined', () {
    final String script = windowsElevated(
      r'exit $code',
      executable: r'C:\Program Files\Nebula VPN\NebulaVPN.exe',
    );
    final String encoded = RegExp(
      r"-EncodedCommand ([A-Za-z0-9+/=]+)",
    ).firstMatch(script)!.group(1)!;
    final List<int> bytes = base64Decode(encoded);

    expect(RegExp('-Verb RunAs').allMatches(script), hasLength(1));
    expect(script, contains('exit 1223'));
    expect(String.fromCharCodes(bytes.where((int b) => b != 0)), r'exit $code');
  });

  // Asked for powershell.exe, Windows' permission prompt said "Windows
  // PowerShell"; asked for the app itself, it names Nebula VPN.
  test('asks Windows to run the app itself, not PowerShell', () {
    final String script = windowsElevated(
      r'exit $code',
      executable: r'C:\Program Files\Nebula VPN\NebulaVPN.exe',
    );

    expect(
      script,
      contains(
        r"Start-Process -FilePath 'C:\Program Files\Nebula VPN\NebulaVPN.exe' "
        "-ArgumentList '--nebula-elevated -NoProfile",
      ),
    );
    expect(script, isNot(contains("'powershell.exe'")));
  });

  // The service reads its config on every start; the temporary file it was
  // installed from used to be deleted at once, so the first restart failed.
  test('installs from a copy only administrators can read', () {
    const WindowsWireGuardTunnel tunnel = WindowsWireGuardTunnel(
      environment: <String, String>{'ProgramFiles': r'D:\Program Files'},
    );
    const String kept = r'D:\Program Files\Nebula VPN\tunnel\nebula.conf';

    final String connect = tunnel.connectScript(
      r'C:\WG\wireguard.exe',
      r'C:\Users\A B\Temp\nebula.conf',
    );

    expect(
      connect.indexOf('/uninstalltunnelservice'),
      lessThan(connect.indexOf('/installtunnelservice')),
    );
    expect(connect, contains("/grant:r '*S-1-5-18:(OI)(CI)F'"));
    expect(
      connect,
      contains(
        r"Copy-Item -LiteralPath 'C:\Users\A B\Temp\nebula.conf' "
        "-Destination '$kept'",
      ),
    );
    expect(connect, contains("'\"/installtunnelservice\"', '\"$kept\"'"));
    expect(
      tunnel.disconnectScript(r'C:\WG\wireguard.exe'),
      contains(
        r"Remove-Item -LiteralPath 'D:\Program Files\Nebula VPN\tunnel'",
      ),
    );
  });

  // Run by the app, wg.exe gets "Access is denied", so the app showed
  // Protected over a tunnel whose server never answered -- and the PC's
  // whole connection went into it. The elevated step checks instead.
  test('takes the tunnel down again when its server never answers', () {
    const WindowsWireGuardTunnel tunnel = WindowsWireGuardTunnel(
      environment: <String, String>{'ProgramFiles': r'D:\Program Files'},
    );

    final List<String> lines = tunnel
        .connectScript(r'C:\WG\wireguard.exe', r'C:\T\nebula.conf')
        .split('\n');
    final int installed = lines.indexWhere(
      (String line) => line.contains('/installtunnelservice'),
    );
    final int waited = lines.indexWhere(
      (String line) => line.contains(r"& 'C:\WG\wg.exe' show nebula"),
    );

    const String removeConfig =
        r"Remove-Item -LiteralPath 'D:\Program Files\Nebula VPN\tunnel' "
        '-Recurse -Force -ErrorAction SilentlyContinue';
    // Neither failure leaves the private key behind: a later disconnect
    // finds no tunnel installed and would never remove it.
    expect(lines[installed + 1], 'if (\$code) { $removeConfig; exit \$code }');
    expect(
      lines,
      contains(contains("'WireGuardTunnel\$nebula' start= demand")),
    );
    expect(waited, greaterThan(installed));
    expect(lines[lines.length - 3], contains('/uninstalltunnelservice'));
    expect(lines[lines.length - 2], removeConfig);
    expect(lines.last, 'exit 1460');
  });

  // wireguard.exe answers errors with a message box and waits for OK. Asked
  // to remove a tunnel that was not installed, it did, hidden, and connect
  // hung behind it until someone found the box.
  test('never waits on wireguard.exe for more than 30 s', () {
    const WindowsWireGuardTunnel tunnel = WindowsWireGuardTunnel(
      environment: <String, String>{'ProgramFiles': r'D:\Program Files'},
    );
    final List<String> connect = tunnel
        .connectScript(r'C:\WG\wireguard.exe', r'C:\T\nebula.conf')
        .split('\n');
    final List<String> steps = <String>[
      ...connect,
      ...tunnel.disconnectScript(r'C:\WG\wireguard.exe').split('\n'),
    ].where((String line) => line.contains('wireguard.exe')).toList();

    expect(steps, isNotEmpty);
    for (final String step in steps) {
      expect(step, contains(r'WaitForExit(30000)'));
      expect(step, isNot(contains('-Wait ')));
    }
    expect(
      connect.firstWhere((String l) => l.contains('/uninstalltunnelservice')),
      startsWith(r"if (Get-Service -Name 'WireGuardTunnel$nebula'"),
    );
  });

  test('says so when it is not installed', () {
    final WindowsWireGuardTunnel tunnel = WindowsWireGuardTunnel(
      environment: const <String, String>{},
      exists: (String path) => false,
    );

    expect(tunnel.findTool('wireguard.exe'), isNull);
  });
}
