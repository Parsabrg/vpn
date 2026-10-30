import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_v2ray_client/flutter_v2ray.dart';

import '../tunnel/tunnel_traffic.dart';
import 'linux_xray_tunnel.dart';
import 'windows_xray_tunnel.dart';

/// Establishes/tears down the real local Xray tunnel -- kept separate from
/// [TunnelController] rather than force-fit into it: that interface's
/// `connect(String configText)` is shaped around a WireGuard `.conf` text
/// blob, while `flutter_v2ray_client` takes a full V2Ray/Xray JSON config
/// and has its own permission/init lifecycle (see [AndroidXrayTunnelController]).
abstract interface class XrayTunnelController {
  /// Android only: must be granted (via system consent UI) before [connect]
  /// can succeed. Platforms with no such consent step return true.
  Future<bool> requestPermission();

  /// [excludedPackages] routes those Android apps around the tunnel, via
  /// the VpnService disallow list the backend already accepts.
  /// [routes] is the address space the tunnel claims. Everything by default;
  /// a shorter list is how the local network is left reachable.
  /// [sessionName] titles the notification, and is the name Android shows
  /// for the VPN in its own "Connected to" line.
  /// [notificationShowsSpeed] puts the live speed on that notification.
  /// [disconnectLabel] is its button, in the app's language.
  /// [proxyOnly] runs the engine as a local proxy with no VPN at all.
  Future<void> connect(
    String xrayConfigJson, {
    List<String> excludedPackages = const <String>[],
    List<String>? routes,
    String sessionName = 'Nebula',
    bool notificationShowsSpeed = true,
    String disconnectLabel = 'Disconnect',
    bool proxyOnly = false,
    bool killSwitch = false,
  });

  Future<void> disconnect();

  /// Starts receiving status and counters from a tunnel already running,
  /// one an earlier run of the app started. Nothing is started or stopped.
  Future<void> attach();

  /// Readings from the running tunnel, as the backend reports them.
  ///
  /// A stream rather than a poll because this backend pushes: the same status
  /// callback that reports CONNECTED carries the counters, so asking on a
  /// timer would add a second clock that can only ever lag the one already
  /// arriving.
  Stream<TunnelTraffic> get traffic;

  /// What the core has said about itself, newest last.
  ///
  /// Read on demand rather than streamed: this is something somebody opens
  /// when a connection is not working, not something the app watches. An
  /// empty list is a normal answer -- the core is quiet when it is healthy,
  /// and on a platform with no core there is nothing to say.
  Future<List<String>> logs();

  /// Discards what has been collected so far. Returns whether it worked.
  Future<bool> clearLogs();

  /// Whether the engine process behind the tunnel is still running: false
  /// once it has stopped, null where this platform cannot tell or nothing
  /// was started. An interface can outlive the engine that fed it; see
  /// tunnel_health.dart.
  Future<bool?> engineRunning();

  /// A real request through [config]'s outbound, v2ray's "real delay": the
  /// milliseconds it took, a negative number when it failed, or null where
  /// this platform cannot measure one at all -- reported as such rather than
  /// as a failure, which would say the profile is broken.
  Future<int?> measureDelay(String config, {required String url});

  /// Megabits a second over a download of [url] through [config]'s outbound;
  /// negative when nothing arrived, null where this platform cannot measure
  /// it (Android: the plugin measures delay only).
  Future<double?> measureDownload(String config, {required String url});
}

class AndroidXrayTunnelController implements XrayTunnelController {
  AndroidXrayTunnelController() {
    _v2ray = V2ray(onStatusChanged: _handleStatusChanged);
  }

  late final V2ray _v2ray;

  /// `V2ray.initialize` sets up the plugin's notification channel and status
  /// listener; it must run once before permission/start calls, but the
  /// underlying plugin has no idempotency guard of its own, so this class
  /// provides one.
  bool _initialized = false;

  /// `startV2Ray` only dispatches the connect request -- the plugin's own
  /// docs say it "completes when the service starts", but that's the native
  /// call returning, not the tunnel actually coming up. The real outcome
  /// only ever arrives asynchronously through [onStatusChanged]'s `state`
  /// field ('CONNECTED'/'DISCONNECTED'/...), confirmed against the plugin's
  /// own V2RayStatus model -- awaiting startV2Ray alone and declaring
  /// success let the app report "Connected" with no VpnService ever
  /// registered on a real device. Only a real 'CONNECTED' event resolves
  /// this; every other state is treated as "not yet known" rather than a
  /// definitive failure, since a transient DISCONNECTED can appear during
  /// the plugin's own startup sequence before it settles -- a stuck
  /// connection attempt still surfaces, via the timeout in [connect].
  Completer<void>? _connectCompleter;

  /// Broadcast: the connect screen subscribes and unsubscribes as it is
  /// shown and hidden, and the controller outlives it.
  final StreamController<TunnelTraffic> _traffic =
      StreamController<TunnelTraffic>.broadcast();

  @override
  Stream<TunnelTraffic> get traffic => _traffic.stream;

  /// The backend's own last word on the core: CONNECTED or DISCONNECTED.
  /// Null until it has said anything this run.
  String? _lastState;

  void _handleStatusChanged(V2RayStatus status) {
    _lastState = status.state;
    if (status.state == 'CONNECTED') {
      _connectCompleter?.complete();
    }
    if (_traffic.hasListener) {
      _traffic.add(
        TunnelTraffic(
          // The backend names these from this device's side already --
          // `download` is what arrived here -- so they map straight across.
          rxBytes: status.download,
          txBytes: status.upload,
          elapsed: parseTunnelDuration(status.duration),
        ),
      );
    }
  }

  Future<void> _ensureInitialized() async {
    if (_initialized) {
      return;
    }
    await _v2ray.initialize(
      // The mark's silhouette, not the launcher icon: a notification's small
      // icon is drawn from its alpha alone. See res/drawable/ic_stat_nebula.
      notificationIconResourceType: 'drawable',
      notificationIconResourceName: 'ic_stat_nebula',
    );
    _initialized = true;
  }

  /// Routes the tunnel claims. Passed as `bypassSubnets`, which despite the
  /// name is the plugin's *included* route list -- supplying it replaces the
  /// IPv4 default route it would otherwise add alone
  /// (V2rayVPNService.setup()).
  ///
  /// The IPv6 default route is the point. Left off, the tunnel claims IPv4
  /// only and Android sends IPv6 straight out of the underlying network,
  /// around the tunnel: on an IPv6-capable network the real address is exposed
  /// to every host that supports it, and that traffic is subject to whatever
  /// the local network does to it, while the app still reports "connected".
  ///
  /// Claiming `::/0` captures it instead. Nothing downstream carries IPv6 --
  /// tun2socks is started with IPv4 netif arguments only -- so those packets
  /// enter the tunnel and are dropped rather than forwarded. That is the
  /// intent, not a shortfall: clients see IPv6 as unreachable and fall back to
  /// IPv4 over the tunnel, which is the behaviour that keeps the address
  /// hidden. Actually carrying IPv6 end to end would mean IPv6 netif
  /// arguments and an outbound proven to carry it, and is worth doing only
  /// once there is a network to verify it against.
  static const List<String> _tunnelRoutes = <String>['0.0.0.0/0', '::/0'];

  @override
  Future<bool> requestPermission() async {
    await _ensureInitialized();
    return _v2ray.requestPermission();
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
    await _ensureInitialized();
    final Completer<void> completer = Completer<void>();
    _connectCompleter = completer;
    try {
      await _v2ray.startV2Ray(
        remark: sessionName,
        config: xrayConfigJson,
        // Named `bypassSubnets` upstream, and the name is wrong: the native
        // service passes each entry to VpnService.Builder.addRoute, so these
        // are the subnets the tunnel *takes*. See tunnel_routes.dart.
        bypassSubnets: routes ?? _tunnelRoutes,
        // Named for what VpnService does -- these packages are disallowed
        // from the tunnel, so their traffic goes out over the normal
        // network rather than being blocked.
        blockedApps: excludedPackages.isEmpty ? null : excludedPackages,
        notificationShowSpeed: notificationShowsSpeed,
        notificationDisconnectButtonName: disconnectLabel,
        proxyOnly: proxyOnly,
      );
      await completer.future.timeout(
        const Duration(seconds: 15),
        onTimeout: () => throw const TunnelStartTimeout(),
      );
    } finally {
      _connectCompleter = null;
    }
  }

  @override
  Future<void> disconnect() => _v2ray.stopV2Ray();

  @override
  Future<void> attach() => _ensureInitialized();

  @override
  Future<List<String>> logs() => _v2ray.getLogs();

  @override
  Future<bool> clearLogs() => _v2ray.clearLogs();

  @override
  // The plugin pushes DISCONNECTED when its core stops, including when the
  // Hysteria2 child it supervises exits; anything else is not a verdict.
  Future<bool?> engineRunning() async => switch (_lastState) {
    'CONNECTED' => true,
    'DISCONNECTED' => false,
    _ => null,
  };

  @override
  Future<int?> measureDelay(String config, {required String url}) async {
    await _ensureInitialized();
    return _v2ray.getServerDelay(config: config, url: url);
  }

  @override
  Future<double?> measureDownload(String config, {required String url}) async =>
      null;
}

/// Every other platform this app can build for -- Windows Xray support is a
/// separate, deferred licensing decision (`flutter_v2ray_client`'s Windows
/// backend is a paid add-on), so this matches [UnsupportedTunnelController]'s
/// "peer provisioned, not yet tunneling" honesty for anything non-Android.
class UnsupportedXrayTunnelController implements XrayTunnelController {
  const UnsupportedXrayTunnelController();

  @override
  // Windows has no Android-style VPN consent API. Returning false here used
  // to make the UI claim that permission was denied even though no Windows
  // prompt had ever been requested. Let [connect] report the actual missing
  // engine instead; the UI asks for Windows tunnel permission before trying.
  Future<bool> requestPermission() async => Platform.isWindows;

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
  }) {
    throw UnsupportedError(
      'Establishing a real Xray tunnel is not supported on this platform yet.',
    );
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<void> attach() async {}

  @override
  Stream<TunnelTraffic> get traffic => const Stream<TunnelTraffic>.empty();

  @override
  Future<List<String>> logs() async => const <String>[];

  @override
  Future<bool> clearLogs() async => true;

  @override
  Future<bool?> engineRunning() async => null;

  @override
  Future<int?> measureDelay(String config, {required String url}) async => null;

  @override
  Future<double?> measureDownload(String config, {required String url}) async =>
      null;
}

final xrayTunnelControllerProvider = Provider<XrayTunnelController>((Ref ref) {
  if (Platform.isAndroid) {
    return AndroidXrayTunnelController();
  }
  if (Platform.isWindows) {
    return WindowsXrayTunnelController();
  }
  if (Platform.isLinux) {
    return LinuxXrayTunnelController();
  }
  return const UnsupportedXrayTunnelController();
});

/// The engine never reported the tunnel up: for Hysteria2, its client never
/// finished the handshake (a network that drops UDP), and the native side
/// tore it down. Said as a protocol that did not get through, not as
/// "something went wrong" (seen on the phone, 2026-10-17).
class TunnelStartTimeout implements Exception {
  const TunnelStartTimeout();

  @override
  String toString() => 'Timed out waiting for the Xray tunnel to connect';
}
