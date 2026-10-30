import 'dart:async';

import 'package:flutter/services.dart';

import '../tunnel/tunnel_traffic.dart';

/// Bridges to each platform's real tunnel bring-up: Android's
/// [MainActivity] (the official WireGuard Android library via JNI) over this
/// channel, or (on Windows) a direct `dart:io` shell-out to the official
/// `wireguard.exe` -- see [WindowsWireGuardTunnel]. Both reuse the real
/// WireGuard implementation rather than reimplementing the protocol.
class NativeTunnelChannel {
  const NativeTunnelChannel();

  static const MethodChannel _channel = MethodChannel(
    'org.nebulavpn/wireguard_tunnel',
  );

  /// Android only: must be granted before [connect] can succeed. A no-op
  /// returning true on platforms with no such consent step.
  Future<bool> requestPermission() async {
    final bool? granted = await _channel.invokeMethod<bool>(
      'requestPermission',
    );
    return granted ?? false;
  }

  /// Android only: whether the user has approved this app as a VPN, found
  /// out without changing anything (see MainActivity.vpnConsentHeld).
  Future<bool> hasPermission() async {
    return await _channel.invokeMethod<bool>('hasPermission') ?? false;
  }

  /// Android only: whose VPN is up, or null where Android does not say.
  Future<String?> vpnOwner() {
    return _channel.invokeMethod<String>('vpnOwner');
  }

  /// Android only: taps on the tunnel notification's Disconnect button.
  ///
  /// The first listener also receives the tap that launched the app, if one
  /// did. One listener at a time: the channel has a single handler.
  Stream<void> disconnectRequests() {
    late final StreamController<void> requests;
    Future<void> take() async {
      final bool taken =
          await _channel.invokeMethod<bool>('takeDisconnectRequest') ?? false;
      if (taken && !requests.isClosed) {
        requests.add(null);
      }
    }

    requests = StreamController<void>(
      onListen: () {
        _channel.setMethodCallHandler((MethodCall call) async {
          if (call.method == 'disconnectRequested') {
            await take();
          }
        });
        unawaited(take());
      },
      onCancel: () => _channel.setMethodCallHandler(null),
    );
    return requests.stream;
  }

  Future<void> connect(String configText) async {
    await _channel.invokeMethod<void>('connect', <String, Object?>{
      'config': configText,
    });
  }

  Future<void> disconnect() async {
    await _channel.invokeMethod<void>('disconnect');
  }

  /// Counters for the running tunnel, or null when none is up.
  ///
  /// Null is carried all the way through rather than collapsed to zeroes: a
  /// tunnel that is down and one that has carried nothing are different, and
  /// the screen draws them differently.
  /// Counters for the VPN interface itself, whichever transport built it.
  ///
  /// The engine-specific readings above only exist for engines this app runs
  /// in-process. Hysteria2 is a child process with no counters to ask, so
  /// this reads what the kernel counted crossing the tunnel -- payload, which
  /// means the same thing the Xray counters mean, and excludes this app's own
  /// calls to the control plane.
  Future<TunnelTraffic?> readTunTraffic() async {
    final Map<Object?, Object?>? reading = await _channel
        .invokeMethod<Map<Object?, Object?>>('readTunTraffic');
    if (reading == null) {
      return null;
    }
    final Object? rx = reading['rxBytes'];
    final Object? tx = reading['txBytes'];
    if (rx is! int || tx is! int) {
      return null;
    }
    return TunnelTraffic(rxBytes: rx, txBytes: tx);
  }

  Future<TunnelTraffic?> readTraffic() async {
    final Map<Object?, Object?>? reading = await _channel
        .invokeMethod<Map<Object?, Object?>>('readTraffic');
    if (reading == null) {
      return null;
    }
    final Object? rx = reading['rxBytes'];
    final Object? tx = reading['txBytes'];
    if (rx is! int || tx is! int) {
      return null;
    }
    // No elapsed: wireguard-go counts bytes, not time, and this process
    // cannot know when a tunnel it did not start came up.
    return TunnelTraffic(rxBytes: rx, txBytes: tx);
  }

  /// Android only: when the running WireGuard tunnel last completed a
  /// handshake, in epoch milliseconds -- 0 when it never has, null when no
  /// tunnel is up.
  Future<int?> wireguardHandshakeMillis() {
    return _channel.invokeMethod<int>('wireguardHandshake');
  }

  /// Android only: the installed version name, from the pubspec version.
  Future<String?> appVersion() {
    return _channel.invokeMethod<String>('appVersion');
  }

  /// Android only: opens an https page in the browser.
  Future<bool> openUrl(Uri url) async {
    try {
      return await _channel.invokeMethod<bool>('openUrl', <String, Object?>{
            'url': url.toString(),
          }) ??
          false;
    } on Object {
      return false;
    }
  }

  /// Opens Android's VPN settings, where the always-on and
  /// block-connections-without-VPN switches live -- the only real kill switch
  /// on the platform, and one no ordinary app can enable for itself.
  ///
  /// Returns false when the screen could not be opened (an OEM build not
  /// exposing the standard action, or a non-Android platform), so the caller
  /// can fall back to telling the user where to look rather than appearing to
  /// have done nothing.
  /// Android's always-on and block-without-VPN switches for this app, as the
  /// tunnel last found them, or null if it never ran since being installed:
  /// only a running VPN service can ask Android.
  Future<({bool alwaysOn, bool lockdown})?> killSwitch() async {
    try {
      final String? state = await _channel.invokeMethod<String>('killSwitch');
      if (state == null || state.length != 2) {
        return null;
      }
      return (alwaysOn: state[0] == '1', lockdown: state[1] == '1');
    } on MissingPluginException {
      return null;
    } on PlatformException {
      return null;
    }
  }

  Future<bool> openVpnSettings() async {
    try {
      final bool? opened = await _channel.invokeMethod<bool>('openVpnSettings');
      return opened ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }
}
