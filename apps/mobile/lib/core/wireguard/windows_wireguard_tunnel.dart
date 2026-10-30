import 'dart:io';

import '../tunnel/tunnel_health.dart';
import '../xray/windows_tunnel_config.dart';

/// The exit code for a declined UAC prompt (Windows' ERROR_CANCELLED).
const int _cancelled = 1223;

/// The exit code for a tunnel whose server never answered (ERROR_TIMEOUT).
const int _noAnswer = 1460;

/// The tunnel came up and its server never answered, so it was taken down
/// again rather than left carrying every packet nowhere.
class WireGuardNoAnswer implements Exception {
  const WireGuardNoAnswer();
}

/// PowerShell that runs [elevated] behind a single UAC prompt and exits with
/// its exit code, or 1223 when the prompt is declined. The prompt names this
/// app: see [windowsElevatedLaunch].
String windowsElevated(String elevated, {String? executable}) {
  final String launch = windowsElevatedLaunch(
    '-NoProfile -NonInteractive -WindowStyle Hidden '
    '-EncodedCommand ${windowsEncodedCommand(elevated)}',
    executable: executable,
  );
  return '''
\$ErrorActionPreference = 'Stop'
try {
  \$p = $launch -Wait -PassThru
} catch {
  exit $_cancelled
}
exit \$p.ExitCode
''';
}

/// Brings a real tunnel up/down on Windows by shelling out to the official,
/// already-installed WireGuard client (`wireguard.exe`) rather than
/// reimplementing the protocol.
///
/// Installing a tunnel service needs administrator rights. This used to run
/// `wireguard.exe` directly on the belief that its manifest asks for them;
/// it does not, so from an unelevated app it failed with "Access is denied"
/// and no UAC prompt ever appeared -- WireGuard never connected on Windows.
/// Each change now goes through one elevated PowerShell, the way the Xray
/// tunnel starts its supervisor.
class WindowsWireGuardTunnel {
  const WindowsWireGuardTunnel({this._environment, this._exists});

  static const String _tunnelName = 'nebula';

  final Map<String, String>? _environment;
  final bool Function(String path)? _exists;

  /// Where WireGuard for Windows is installed, found rather than assumed.
  ///
  /// This used to be `C:\Program Files\WireGuard\wireguard.exe`, which is
  /// wrong on any machine whose system drive is not C:, whose Program Files
  /// is redirected, or where WireGuard went somewhere else. Checked in order:
  /// an explicit `NEBULA_WIREGUARD_DIR`, both Program Files locations the
  /// system reports, then every directory on PATH.
  String? findTool(String executable) {
    final Map<String, String> environment =
        _environment ?? Platform.environment;
    final bool Function(String) exists =
        _exists ?? (String path) => File(path).existsSync();
    final List<String> directories = <String>[
      if (environment['NEBULA_WIREGUARD_DIR'] case final String dir) dir,
      for (final String variable in const <String>[
        'ProgramFiles',
        'ProgramW6432',
      ])
        if (environment[variable] case final String root) '$root\\WireGuard',
      ...?environment['PATH']?.split(';'),
    ];
    for (final String directory in directories) {
      if (directory.trim().isEmpty) {
        continue;
      }
      final String candidate =
          '${directory.trim().replaceAll(RegExp(r'[\\/]+$'), '')}\\$executable';
      if (exists(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  String _requireWireGuard() {
    final String? path = findTool('wireguard.exe');
    if (path == null) {
      throw StateError(
        'The WireGuard for Windows client was not found. Install it from '
        'https://www.wireguard.com/install/, set NEBULA_WIREGUARD_DIR to where '
        'it is installed, or choose an Xray or Hysteria2 protocol.',
      );
    }
    return path;
  }

  Future<void> connect(String configText) async {
    final String wireGuard = _requireWireGuard();
    final Directory dir = await Directory.systemTemp.createTemp('nebula-wg-');
    final File configFile = File('${dir.path}\\$_tunnelName.conf');
    try {
      await configFile.writeAsString(configText);
      await _runElevated(connectScript(wireGuard, configFile.path), 'install');
    } finally {
      await dir.delete(recursive: true);
    }
  }

  Future<void> disconnect() async {
    final String? wireGuard = findTool('wireguard.exe');
    // Asking for elevation to remove a tunnel that is not there would put a
    // UAC prompt in front of every sign-out.
    if (wireGuard == null || !await _tunnelInstalled()) {
      return;
    }
    await _runElevated(disconnectScript(wireGuard), 'uninstall');
  }

  /// Where the installed tunnel's config lives. The service reads it on
  /// every start -- after a reboot, a sleep, a restart after a failure -- so
  /// it cannot be the temporary file this app writes: that used to be
  /// deleted straight after installing, and the next start failed with "The
  /// system cannot find the path specified". It holds the private key, so
  /// only SYSTEM and Administrators may read it.
  String get _configDirectory {
    final String programFiles =
        (_environment ?? Platform.environment)['ProgramFiles'] ??
        r'C:\Program Files';
    return '$programFiles\\Nebula VPN\\tunnel';
  }

  /// The elevated PowerShell that replaces any installed tunnel with the
  /// one in [configPath], and takes it down again unless its server answers.
  ///
  /// The handshake is checked here because only an elevated process can
  /// read it: `wg.exe` run by the app gets "Access is denied", so the app
  /// could never tell, took the tunnel at its word, and showed Protected
  /// over one that went nowhere -- with this PC's whole connection in it.
  String connectScript(String wireGuard, String configPath) {
    final String dir = _configDirectory;
    final String kept = '$dir\\$_tunnelName.conf';
    final String wg = windowsPowerShellLiteral(
      '${wireGuard.substring(0, wireGuard.lastIndexOf(r'\'))}\\wg.exe',
    );
    final String uninstall = _wireGuardStep(wireGuard, <String>[
      '/uninstalltunnelservice',
      _tunnelName,
    ]);
    return <String>[
      r"$ErrorActionPreference = 'Stop'",
      // Only when one is installed: wireguard.exe answers a missing tunnel
      // with a message box, not an error code (see [_wireGuardStep]).
      "if (Get-Service -Name 'WireGuardTunnel\$$_tunnelName' -ErrorAction SilentlyContinue) { $uninstall }",
      'New-Item -ItemType Directory -Force -Path ${windowsPowerShellLiteral(dir)} | Out-Null',
      // SYSTEM and Administrators, by SID: group names are localized.
      "icacls.exe ${windowsPowerShellLiteral(dir)} /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null",
      r'if ($LASTEXITCODE) { exit $LASTEXITCODE }',
      'Copy-Item -LiteralPath ${windowsPowerShellLiteral(configPath)} -Destination ${windowsPowerShellLiteral(kept)} -Force',
      _wireGuardStep(wireGuard, <String>['/installtunnelservice', kept]),
      // A failed connect leaves no copy of the private key behind: a later
      // disconnect finds no tunnel installed and would never remove it.
      'if (\$code) { $_removeConfig; exit \$code }',
      // Installed tunnels start with Windows. One that comes up at boot
      // with the app closed, and a server it cannot reach, cuts the PC off
      // with nothing on screen to say why. The app brings it up.
      "sc.exe config 'WireGuardTunnel\$$_tunnelName' start= demand | Out-Null",
      // WireGuard retries its handshake every five seconds.
      r'for ($i = 0; $i -lt 20; $i++) {',
      '  Start-Sleep -Seconds 1',
      "  try { \$h = & $wg show $_tunnelName latest-handshakes 2>\$null } catch { \$h = '' }",
      r"""  if ("$h" -match '\s[1-9]\d*\s*$') { exit 0 }""",
      '}',
      uninstall,
      _removeConfig,
      'exit $_noAnswer',
    ].join('\n');
  }

  /// The elevated PowerShell that removes the tunnel and its config.
  String disconnectScript(String wireGuard) => <String>[
    r"$ErrorActionPreference = 'Stop'",
    _wireGuardStep(wireGuard, <String>['/uninstalltunnelservice', _tunnelName]),
    _removeConfig,
    r'exit $code',
  ].join('\n');

  /// Removes the installed tunnel's config, which holds its private key.
  String get _removeConfig =>
      'Remove-Item -LiteralPath ${windowsPowerShellLiteral(_configDirectory)} -Recurse -Force -ErrorAction SilentlyContinue';

  /// One run of `wireguard.exe`, given at most 30 s.
  ///
  /// wireguard.exe is a GUI program: an error is a message box, not an exit
  /// code, and it waits for someone to press OK. Removing a tunnel that was
  /// not installed did exactly that, hidden behind the app, and a connect
  /// hung on it for as long as nobody found the box.
  String _wireGuardStep(String wireGuard, List<String> arguments) =>
      '\$p = Start-Process -FilePath ${windowsPowerShellLiteral(wireGuard)} '
      '-ArgumentList ${arguments.map((String a) => windowsPowerShellLiteral('"$a"')).join(', ')} '
      '-WindowStyle Hidden -PassThru; \$null = \$p.Handle; '
      'if (\$p.WaitForExit(30000)) { \$code = \$p.ExitCode } '
      // 258: Windows' WAIT_TIMEOUT -- the step, not the server, is at fault.
      'else { \$p.Kill(); \$code = 258 }';

  Future<bool> _tunnelInstalled() async {
    final ProcessResult result = await Process.run('sc.exe', const <String>[
      'query',
      'WireGuardTunnel\$$_tunnelName',
    ]);
    return result.exitCode == 0;
  }

  Future<void> _runElevated(String elevated, String step) async {
    final ProcessResult result = await Process.run('powershell.exe', <String>[
      '-NoProfile',
      '-NonInteractive',
      '-WindowStyle',
      'Hidden',
      '-EncodedCommand',
      windowsEncodedCommand(windowsElevated(elevated)),
    ]);
    if (result.exitCode == _cancelled) {
      throw StateError('Windows VPN permission was not granted.');
    }
    if (result.exitCode == _noAnswer) {
      throw const WireGuardNoAnswer();
    }
    if (result.exitCode != 0) {
      throw StateError(
        'wireguard.exe could not $step the tunnel (${result.exitCode}).',
      );
    }
  }

  /// The tunnel's latest handshake, from `wg.exe show nebula
  /// latest-handshakes`; null when the tool or the tunnel is absent.
  Future<DateTime?> latestHandshake() async {
    final String? wg = findTool('wg.exe');
    if (wg == null) {
      return null;
    }
    try {
      final ProcessResult result = await Process.run(wg, const <String>[
        'show',
        _tunnelName,
        'latest-handshakes',
      ]);
      if (result.exitCode != 0) {
        return null;
      }
      return parseLatestHandshakes(result.stdout as String);
    } on ProcessException {
      return null;
    }
  }
}
