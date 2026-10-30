import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

/// The argument a sign-in start is given, so Windows opens it in the tray.
const String startHiddenArgument = '--hidden';

/// Starts Nebula VPN when the person signs in to Windows or Linux.
///
/// The operating system holds the setting, so there is nothing to keep in
/// step with it: Windows reads the Run key, Linux desktops read
/// `~/.config/autostart`.
class LoginItem {
  const LoginItem();

  static const String _runKey =
      r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
  static const String _name = 'Nebula VPN';

  Future<bool> enabled() async {
    if (Platform.isWindows) {
      final ProcessResult result = await Process.run('reg.exe', <String>[
        'query',
        _runKey,
        '/v',
        _name,
      ]);
      return result.exitCode == 0;
    }
    return linuxAutostartFile(Platform.environment).existsSync();
  }

  // ponytail: the entry names this install's path, so moving the app leaves
  // it pointing nowhere until the switch is turned off and on again.
  Future<void> set({required bool enabled}) async {
    if (Platform.isWindows) {
      // A refusal is not thrown: the switch reads the answer back from
      // Windows, so it shows what was actually saved.
      await Process.run(
        'reg.exe',
        enabled
            ? <String>[
                'add',
                _runKey,
                '/v',
                _name,
                '/t',
                'REG_SZ',
                '/d',
                '"${Platform.resolvedExecutable}" $startHiddenArgument',
                '/f',
              ]
            : <String>['delete', _runKey, '/v', _name, '/f'],
      );
      return;
    }
    final File file = linuxAutostartFile(Platform.environment);
    if (!enabled) {
      if (file.existsSync()) {
        file.deleteSync();
      }
      return;
    }
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(
      linuxAutostartEntry(
        // An AppImage's own path is a mount that is gone after this run.
        Platform.environment['APPIMAGE'] ?? Platform.resolvedExecutable,
      ),
    );
  }
}

File linuxAutostartFile(Map<String, String> environment) {
  final String? configured = environment['XDG_CONFIG_HOME'];
  final String config = configured != null && configured.isNotEmpty
      ? configured
      : '${environment['HOME']}/.config';
  return File('$config/autostart/nebula-vpn.desktop');
}

String linuxAutostartEntry(String executable) {
  // The Exec key's own quoting: these four are escaped inside double quotes.
  final String quoted = executable.replaceAllMapped(
    RegExp(r'["`$\\]'),
    (Match match) => '\\${match[0]}',
  );
  return '[Desktop Entry]\n'
      'Type=Application\n'
      'Name=Nebula VPN\n'
      'Exec="$quoted"\n'
      'X-GNOME-Autostart-enabled=true\n';
}

final loginItemProvider = Provider<LoginItem>((Ref ref) => const LoginItem());

final loginItemEnabledProvider = FutureProvider<bool>(
  (Ref ref) => ref.watch(loginItemProvider).enabled(),
);
