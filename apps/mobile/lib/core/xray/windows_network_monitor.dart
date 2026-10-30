import 'dart:io';

import '../tunnel/tunnel_traffic.dart';

/// Reads live interface traffic counters from Windows via netsh.
/// This works across all tunnel protocols (WireGuard, Xray, Hysteria)
/// that use the "Nebula" network adapter.
class WindowsNetworkMonitor {
  const WindowsNetworkMonitor();

  /// The adapter's line in `netsh interface ipv4 show subinterfaces`.
  ///
  /// Either case: Xray and Hysteria name their adapter "Nebula", but a
  /// WireGuard tunnel's adapter takes the tunnel's name, "nebula". Matched
  /// case-sensitively, a WireGuard tunnel was never this app's own: the
  /// traffic figures stayed blank, and two readings later the tunnel watch
  /// took it for replaced by another VPN and disconnected it, seconds after
  /// it came up.
  static RegExpMatch? matchSubinterface(String netshOutput) => RegExp(
    r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+Nebula\s*$',
    multiLine: true,
    caseSensitive: false,
  ).firstMatch(netshOutput);

  /// Reads current rx (Bytes In) and tx (Bytes Out) counts on the Nebula adapter.
  static Future<TunnelTraffic?> readTraffic() async {
    try {
      final ProcessResult result = await Process.run(
        'netsh.exe',
        const <String>['interface', 'ipv4', 'show', 'subinterfaces', 'Nebula'],
      );
      if (result.exitCode != 0) {
        return null;
      }
      final RegExpMatch? match = matchSubinterface(result.stdout as String);
      if (match != null) {
        final int rx = int.tryParse(match.group(3)!) ?? 0;
        final int tx = int.tryParse(match.group(4)!) ?? 0;
        return TunnelTraffic(rxBytes: rx, txBytes: tx);
      }
    } catch (_) {}
    return null;
  }

  /// Whether the Nebula adapter is present and reported Up (MediaSenseState == 1).
  static Future<bool> isAdapterUp() async {
    try {
      final ProcessResult result = await Process.run(
        'netsh.exe',
        const <String>['interface', 'ipv4', 'show', 'subinterfaces', 'Nebula'],
      );
      if (result.exitCode != 0) {
        return false;
      }
      final RegExpMatch? match = matchSubinterface(result.stdout as String);
      if (match != null) {
        final int mediaSenseState = int.tryParse(match.group(2)!) ?? 0;
        return mediaSenseState == 1;
      }
    } catch (_) {}
    return false;
  }
}
