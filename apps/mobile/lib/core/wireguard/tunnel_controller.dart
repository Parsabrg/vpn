import 'dart:io' show Platform;

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../tunnel/tunnel_traffic.dart';
import '../xray/windows_network_monitor.dart';
import 'linux_wireguard_tunnel.dart';
import 'native_tunnel_channel.dart';
import 'windows_wireguard_tunnel.dart';
import 'wireguard_config.dart';

/// Establishes/tears down the real local tunnel for whatever the current
/// platform actually supports -- one interface, one implementation per
/// platform, matching this codebase's existing repository-interface
/// pattern (e.g. [ServerRepository]).
abstract interface class TunnelController {
  /// Android only: must be granted (via system consent UI) before [connect]
  /// can succeed. Platforms with no such consent step return true.
  Future<bool> requestPermission();

  /// [excludedPackages] routes those Android apps around the tunnel. Ignored
  /// by platforms with no per-app routing rather than rejected, so a caller
  /// does not have to know which platform it is on to ask.
  Future<void> connect(
    String configText, {
    List<String> excludedPackages = const <String>[],
    bool killSwitch = false,
  });

  Future<void> disconnect();

  /// Counters for the running tunnel, or null when none is up or the
  /// platform cannot report them.
  Future<TunnelTraffic?> readTraffic();

  /// Counters for the VPN interface, whichever transport built it. Used
  /// for transports whose engine this app does not run in-process.
  Future<TunnelTraffic?> readTunTraffic();

  /// Whether VPN consent is already held, so connecting would not raise a
  /// system dialog nobody asked for. Changes nothing to find out.
  Future<bool> hasPermission();

  /// Whether the running tunnel has completed a handshake with its server:
  /// true once it has, false while it has not, null where the platform
  /// cannot say or no tunnel is up.
  ///
  /// [connect] returning says only that the interface exists. On a network
  /// that drops WireGuard it exists all the same, and carries nothing.
  Future<bool?> hasHandshake();

  /// When the running tunnel last completed a handshake: the Unix epoch if it
  /// never has, null where the platform cannot say or no tunnel is up.
  ///
  /// [hasHandshake] answers "ever"; this answers "recently", which is what
  /// tells a live session from one whose server stopped answering an hour
  /// ago behind an interface that is still up. See tunnel_health.dart.
  Future<DateTime?> latestHandshake();

  /// Whose VPN is up, or null where the platform cannot tell.
  ///
  /// Null rather than a guess, because the answer is acted on: [VpnOwner.own]
  /// is what a tunnel is adopted and stopped on, and anything else is what
  /// takes "Protected" off the screen.
  Future<VpnOwner?> activeVpn();

  /// Taps on the tunnel notification's Disconnect button, including the one
  /// that launched the app. Empty where there is no such notification.
  Stream<void> disconnectRequests();
}

/// Whose VPN, if any, is the device's.
enum VpnOwner {
  /// No VPN is up.
  none,

  /// This app's tunnel.
  own,

  /// Another app's. Never stopped or adopted from here.
  other,
}

class AndroidTunnelController implements TunnelController {
  const AndroidTunnelController(this._channel);

  final NativeTunnelChannel _channel;

  @override
  Future<bool> requestPermission() => _channel.requestPermission();

  @override
  Future<void> connect(
    String configText, {
    List<String> excludedPackages = const <String>[],
    bool killSwitch = false,
  }) {
    return _channel.connect(
      withExcludedApplications(configText, excludedPackages),
    );
  }

  @override
  Future<void> disconnect() => _channel.disconnect();

  @override
  Future<TunnelTraffic?> readTraffic() => _channel.readTraffic();

  @override
  Future<TunnelTraffic?> readTunTraffic() => _channel.readTunTraffic();

  @override
  Future<bool> hasPermission() => _channel.hasPermission();

  @override
  Future<bool?> hasHandshake() async {
    final DateTime? latest = await latestHandshake();
    return latest == null ? null : latest.millisecondsSinceEpoch > 0;
  }

  @override
  Future<DateTime?> latestHandshake() async {
    try {
      final int? millis = await _channel.wireguardHandshakeMillis();
      return millis == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true);
    } on Object {
      // Not knowing is not the same as knowing it failed. A tunnel is never
      // torn down on an answer this side could not get.
      return null;
    }
  }

  @override
  Future<VpnOwner?> activeVpn() async {
    return switch (await _channel.vpnOwner()) {
      'own' => VpnOwner.own,
      'other' => VpnOwner.other,
      'none' => VpnOwner.none,
      _ => null,
    };
  }

  @override
  Stream<void> disconnectRequests() => _channel.disconnectRequests();
}

class WindowsTunnelController implements TunnelController {
  const WindowsTunnelController(this._tunnel);

  final WindowsWireGuardTunnel _tunnel;

  @override
  Future<bool> requestPermission() async => true;

  @override
  // Exclusions are dropped here on purpose. `ExcludedApplications` is an
  // Android concept -- Windows routes by interface, not by process -- and
  // quietly writing the key into a config wireguard.exe rejects would fail
  // the whole tunnel rather than skip a feature.
  Future<void> connect(
    String configText, {
    List<String> excludedPackages = const <String>[],
    bool killSwitch = false,
  }) => _tunnel.connect(configText);

  @override
  Future<void> disconnect() => _tunnel.disconnect();

  @override
  // Reads the Nebula adapter's byte counters via netsh, which works for
  // every transport that creates the adapter (WireGuard, Xray, Hysteria).
  Future<TunnelTraffic?> readTraffic() => WindowsNetworkMonitor.readTraffic();

  @override
  Future<TunnelTraffic?> readTunTraffic() =>
      WindowsNetworkMonitor.readTraffic();

  @override
  Future<bool> hasPermission() async => true;

  @override
  Future<bool?> hasHandshake() async {
    final DateTime? latest = await latestHandshake();
    return latest == null ? null : latest.millisecondsSinceEpoch > 0;
  }

  @override
  // Read from `wg.exe`, which ships beside wireguard.exe. This used to be
  // null always, and null counts as "answered" at connect -- so Windows
  // showed Protected without ever knowing the server replied.
  Future<DateTime?> latestHandshake() => _tunnel.latestHandshake();

  @override
  Future<VpnOwner?> activeVpn() async =>
      await WindowsNetworkMonitor.isAdapterUp() ? VpnOwner.own : VpnOwner.none;

  @override
  Stream<void> disconnectRequests() => const Stream<void>.empty();
}

/// Every other platform this app can build for (web, unsupported desktop
/// targets): peer provisioning through the API still works, but there is no
/// local tunnel to bring up yet, matching this project's existing "peer
/// provisioned, not yet tunneling" honesty elsewhere.
class UnsupportedTunnelController implements TunnelController {
  const UnsupportedTunnelController();

  @override
  Future<bool> requestPermission() async => false;

  @override
  Future<void> connect(
    String configText, {
    List<String> excludedPackages = const <String>[],
    bool killSwitch = false,
  }) {
    throw UnsupportedError(
      'Establishing a real WireGuard tunnel is not supported on this platform yet.',
    );
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<TunnelTraffic?> readTraffic() async => null;

  @override
  Future<TunnelTraffic?> readTunTraffic() async => null;

  @override
  Future<bool> hasPermission() async => false;

  @override
  Future<bool?> hasHandshake() async => null;

  @override
  Future<VpnOwner?> activeVpn() async => null;

  @override
  Future<DateTime?> latestHandshake() async => null;

  @override
  Stream<void> disconnectRequests() => const Stream<void>.empty();
}

final tunnelControllerProvider = Provider<TunnelController>((Ref ref) {
  if (Platform.isAndroid) {
    return const AndroidTunnelController(NativeTunnelChannel());
  }
  if (Platform.isWindows) {
    return const WindowsTunnelController(WindowsWireGuardTunnel());
  }
  if (Platform.isLinux) {
    return LinuxTunnelController();
  }
  return const UnsupportedTunnelController();
});
