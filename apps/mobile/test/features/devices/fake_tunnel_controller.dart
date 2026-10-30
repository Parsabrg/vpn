import 'dart:async';

import 'package:nebula_mobile/core/tunnel/tunnel_traffic.dart';
import 'package:nebula_mobile/core/wireguard/tunnel_controller.dart';

class FakeTunnelController implements TunnelController {
  bool permissionGranted = true;
  Object? connectError;

  int requestPermissionCalls = 0;
  int connectCalls = 0;
  int disconnectCalls = 0;
  int readTrafficCalls = 0;
  int readTunTrafficCalls = 0;
  String? lastConnectConfig;

  /// Null by default, matching a tunnel that is not up.
  TunnelTraffic? traffic;

  /// What the VPN interface reports, independent of the engine.
  TunnelTraffic? tunTraffic;
  Object? readTrafficError;
  List<String> lastExcludedPackages = const <String>[];
  bool? lastKillSwitch;

  /// Consent already held, as opposed to [permissionGranted], which is
  /// what asking for it would return.
  bool permissionHeld = true;

  /// Whose VPN is up, as far as the device is concerned.
  VpnOwner? vpnOwner = VpnOwner.none;

  int activeVpnCalls = 0;

  /// What the running tunnel says about its handshake. True by default: a
  /// server that answers, which is what every other test is about.
  bool? handshake = true;

  /// Answers given in order before [handshake] is used, for a server that
  /// answers only after a few attempts.
  final List<bool?> handshakeAnswers = <bool?>[];

  int hasHandshakeCalls = 0;

  /// Holds [hasHandshake] until completed: a server slow to answer.
  Completer<void>? handshakeGate;

  @override
  Future<bool> hasPermission() async => permissionHeld;

  @override
  Future<bool?> hasHandshake() async {
    hasHandshakeCalls++;
    await handshakeGate?.future;
    if (handshakeAnswers.isNotEmpty) {
      return handshakeAnswers.removeAt(0);
    }
    return handshake;
  }

  /// When the running tunnel last completed a handshake. Null by default:
  /// the platform cannot say, which the tunnel watch never acts on.
  DateTime? latestHandshakeAt;

  @override
  Future<DateTime?> latestHandshake() async => latestHandshakeAt;

  final StreamController<void> _disconnectRequests =
      StreamController<void>.broadcast();

  /// What tapping Disconnect on the tunnel notification would deliver.
  void tapNotificationDisconnect() => _disconnectRequests.add(null);

  @override
  Stream<void> disconnectRequests() => _disconnectRequests.stream;

  @override
  Future<VpnOwner?> activeVpn() async {
    activeVpnCalls++;
    return vpnOwner;
  }

  @override
  Future<bool> requestPermission() async {
    requestPermissionCalls++;
    return permissionGranted;
  }

  @override
  Future<void> connect(
    String configText, {
    List<String> excludedPackages = const <String>[],
    bool killSwitch = false,
  }) async {
    connectCalls++;
    lastConnectConfig = configText;
    lastExcludedPackages = excludedPackages;
    lastKillSwitch = killSwitch;
    final Object? error = connectError;
    if (error != null) {
      throw error;
    }
    vpnOwner = VpnOwner.own;
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    vpnOwner = VpnOwner.none;
  }

  @override
  Future<TunnelTraffic?> readTraffic() async {
    readTrafficCalls++;
    final Object? error = readTrafficError;
    if (error != null) {
      throw error;
    }
    return traffic;
  }

  @override
  Future<TunnelTraffic?> readTunTraffic() async {
    readTunTrafficCalls++;
    final Object? error = readTrafficError;
    if (error != null) {
      throw error;
    }
    return tunTraffic;
  }
}
