import 'dart:io';

import '../tunnel/tunnel_traffic.dart';
import '../xray/linux_vpn_supervisor.dart';
import 'tunnel_controller.dart';
import 'windows_wireguard_tunnel.dart' show WireGuardNoAnswer;

/// WireGuard on Linux: the kernel's own, set up by the same root helper as
/// the Xray tunnel (see [linuxVpnSupervisorScript]). Also answers for the
/// `nebula` interface whichever transport made it, as Windows does.
class LinuxTunnelController implements TunnelController {
  LinuxTunnelController();

  Directory? _state;

  @override
  Future<bool> requestPermission() async => true;

  @override
  // ExcludedApplications is Android's; Linux routes by interface.
  Future<void> connect(
    String configText, {
    List<String> excludedPackages = const <String>[],
    bool killSwitch = false,
  }) async {
    await disconnect();
    final Directory state = await linuxPrivateTemp('nebula-tun-');
    _state = state;
    try {
      final File config = File('${state.path}/wireguard.conf');
      await config.writeAsString(configText);
      await startLinuxVpnHelper(
        engine: linuxWireGuardEngine,
        config: config,
        dnsServers: linuxWireGuardDns(configText),
        killSwitch: killSwitch,
      );
      // As on Windows: an interface whose server never answers carries
      // every packet nowhere. WireGuard retries its handshake every five
      // seconds.
      for (int i = 0; i < 40; i++) {
        final DateTime? latest = await linuxWireGuardHandshake(state);
        if (latest != null && latest.millisecondsSinceEpoch > 0) {
          return;
        }
        await Future<void>.delayed(const Duration(milliseconds: 500));
      }
      throw const WireGuardNoAnswer();
    } catch (_) {
      await disconnect();
      rethrow;
    }
  }

  @override
  Future<void> disconnect() async {
    final Directory? state = _state;
    _state = null;
    if (state != null) {
      await stopLinuxVpnHelper(state);
    }
  }

  @override
  Future<TunnelTraffic?> readTraffic() => linuxTunnelTraffic();

  @override
  Future<TunnelTraffic?> readTunTraffic() => linuxTunnelTraffic();

  @override
  Future<bool> hasPermission() async => true;

  @override
  Future<bool?> hasHandshake() async {
    final DateTime? latest = await latestHandshake();
    return latest == null ? null : latest.millisecondsSinceEpoch > 0;
  }

  @override
  Future<DateTime?> latestHandshake() async {
    final Directory? state = _state;
    return state == null ? null : linuxWireGuardHandshake(state);
  }

  @override
  Future<VpnOwner?> activeVpn() async =>
      await linuxTunnelUp() ? VpnOwner.own : VpnOwner.none;

  @override
  Stream<void> disconnectRequests() => const Stream<void>.empty();
}

/// The `DNS =` addresses of a WireGuard config; names (search domains) are
/// left out, as the helper takes addresses only.
List<String> linuxWireGuardDns(String configText) => <String>[
  for (final RegExpMatch line in RegExp(
    r'^\s*DNS\s*=\s*(.+)$',
    multiLine: true,
    caseSensitive: false,
  ).allMatches(configText))
    for (final String value in line.group(1)!.split(','))
      if (InternetAddress.tryParse(value.trim()) != null) value.trim(),
];
