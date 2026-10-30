import 'dart:async';

import 'package:nebula_mobile/core/tunnel/tunnel_traffic.dart';
import 'package:nebula_mobile/core/wireguard/tunnel_controller.dart';
import 'package:nebula_mobile/core/xray/xray_tunnel_controller.dart';

import 'fake_tunnel_controller.dart';

class FakeXrayTunnelController implements XrayTunnelController {
  bool permissionGranted = true;
  Object? connectError;

  int requestPermissionCalls = 0;

  /// Called as each connect starts, to see what had happened by then.
  void Function()? onConnect;
  int connectCalls = 0;
  int disconnectCalls = 0;
  String? lastConnectConfig;

  /// Broadcast, like the real one: the screen subscribes and
  /// unsubscribes as it is shown and hidden.
  final StreamController<TunnelTraffic> trafficController =
      StreamController<TunnelTraffic>.broadcast();

  List<String> lastExcludedPackages = const <String>[];

  bool? lastKillSwitch;
  List<String>? lastRoutes;
  String? lastSessionName;
  bool? lastNotificationShowsSpeed;
  String? lastDisconnectLabel;
  bool? lastProxyOnly;

  @override
  Future<bool> requestPermission() async {
    requestPermissionCalls++;
    return permissionGranted;
  }

  @override
  Future<void> connect(
    String xrayConfigJson, {
    List<String> excludedPackages = const <String>[],
    List<String>? routes,
    String sessionName = 'Nebula',
    bool notificationShowsSpeed = true,
    String disconnectLabel = 'Disconnect',
    bool proxyOnly = false,
    bool killSwitch = false,
  }) async {
    connectCalls++;
    onConnect?.call();
    lastConnectConfig = xrayConfigJson;
    lastExcludedPackages = excludedPackages;
    lastKillSwitch = killSwitch;
    lastRoutes = routes;
    lastSessionName = sessionName;
    lastNotificationShowsSpeed = notificationShowsSpeed;
    lastDisconnectLabel = disconnectLabel;
    lastProxyOnly = proxyOnly;
    final Object? error = connectError;
    if (error != null) {
      throw error;
    }
    if (engineAliveAfterConnect case final bool alive) {
      engineAlive = alive;
    }
    sharedVpn?.vpnOwner = VpnOwner.own;
  }

  /// The WireGuard fake whose VPN this engine's connect raises, when a test
  /// needs the two to agree -- on a device both run in the same VpnService.
  FakeTunnelController? sharedVpn;

  /// What [engineAlive] becomes each time a connect succeeds: an engine
  /// that comes back when it is restarted.
  bool? engineAliveAfterConnect;

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
  }

  int attachCalls = 0;

  @override
  Future<void> attach() async {
    attachCalls++;
  }

  List<String> logLines = const <String>[];
  int clearLogCalls = 0;
  Object? logsError;

  @override
  Future<List<String>> logs() async {
    final Object? error = logsError;
    if (error != null) {
      throw error;
    }
    return logLines;
  }

  @override
  Future<int?> measureDelay(String config, {required String url}) async {
    measuredConfigs.add(config);
    await measureGate?.future;
    return delayFor(config);
  }

  /// Null: no download measured unless a test sets this.
  double? Function(String config) downloadFor = (String _) => null;
  final List<String> downloadConfigs = <String>[];

  @override
  Future<double?> measureDownload(String config, {required String url}) async {
    downloadConfigs.add(config);
    return downloadFor(config);
  }

  /// Holds every delay test open until completed.
  Completer<void>? measureGate;

  /// Every config the delay test was run on, in order.
  final List<String> measuredConfigs = <String>[];

  /// What a delay test answers for a config: milliseconds, negative for a
  /// failure, null where the platform cannot measure.
  int? Function(String config) delayFor = (String _) => 120;

  @override
  Future<bool> clearLogs() async {
    clearLogCalls++;
    logLines = const <String>[];
    return true;
  }

  @override
  Stream<TunnelTraffic> get traffic => trafficController.stream;

  /// Whether the engine process is running. Null by default: unknown, which
  /// the tunnel watch never acts on.
  bool? engineAlive;

  @override
  Future<bool?> engineRunning() async => engineAlive;
}
