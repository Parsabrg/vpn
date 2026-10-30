import 'dart:io';

/// Configures Windows system proxy (WinINET) settings so desktop applications
/// and web browsers automatically route through Nebula when running in Local Proxy mode.
class WindowsSystemProxy {
  const WindowsSystemProxy();

  static const String _registryKey =
      r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings';

  /// Enables the Windows system proxy pointing to the local SOCKS/HTTP port.
  static Future<void> enable(int port) async {
    if (!Platform.isWindows) return;
    try {
      await Process.run('reg.exe', <String>[
        'add',
        _registryKey,
        '/v',
        'ProxyEnable',
        '/t',
        'REG_DWORD',
        '/d',
        '1',
        '/f',
      ]);
      await Process.run('reg.exe', <String>[
        'add',
        _registryKey,
        '/v',
        'ProxyServer',
        '/t',
        'REG_SZ',
        '/d',
        'socks=127.0.0.1:$port',
        '/f',
      ]);
      await Process.run('reg.exe', <String>[
        'add',
        _registryKey,
        '/v',
        'ProxyOverride',
        '/t',
        'REG_SZ',
        '/d',
        '<local>;localhost;127.*;10.*;172.16.*;192.168.*',
        '/f',
      ]);
    } catch (_) {}
  }

  /// Disables the Windows system proxy and restores direct network access.
  static Future<void> disable() async {
    if (!Platform.isWindows) return;
    try {
      await Process.run('reg.exe', <String>[
        'add',
        _registryKey,
        '/v',
        'ProxyEnable',
        '/t',
        'REG_DWORD',
        '/d',
        '0',
        '/f',
      ]);
    } catch (_) {}
  }
}
