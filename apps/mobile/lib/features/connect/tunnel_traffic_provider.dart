import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/tunnel/tunnel_traffic.dart';
import '../../core/wireguard/tunnel_controller.dart';
import '../../core/xray/xray_tunnel_controller.dart';
import '../devices/devices_controller.dart';
import '../devices/devices_state.dart';

/// How often a tunnel that does not report on its own is asked.
///
/// One second, because the figure is read while somebody is looking at it and
/// a slower tick reads as a frozen screen. It costs one call into a counter
/// that already exists.
const Duration kTunnelTrafficInterval = Duration(seconds: 1);

/// The transport that runs outside Xray, named once rather than spelled at
/// each site -- the config renderer branches on the same value.
const String hysteriaTransport = 'hysteria';

/// Live readings for the current session, or null when there is no session.
///
/// Nullable on purpose. A provider that simply stopped emitting leaves its
/// last value in place, so the screen went on showing the figures from a
/// tunnel that had already been disconnected. An explicit null is how a
/// session ends.
///
/// Where the readings come from depends on which engine is actually running,
/// and the three are genuinely different rather than inconsistently handled:
/// Xray pushes counters through the same callback that reports CONNECTED;
/// WireGuard holds them inside wireguard-go and has to be asked; Hysteria2 is
/// a child process with no counters at all, so the kernel's own interface
/// counters stand in.
final tunnelTrafficProvider = StreamProvider.autoDispose<TunnelTraffic?>((
  Ref ref,
) {
  final DevicesState state = ref.watch(devicesControllerProvider);
  if (!state.tunnelEstablished) {
    return Stream<TunnelTraffic?>.value(null);
  }

  final Stream<TunnelTraffic> readings;
  if (state.activeProtocolCode == wireguardProtocolCode) {
    readings = _poll(ref.watch(tunnelControllerProvider).readTraffic);
  } else if (state.xrayClient?.transport == hysteriaTransport) {
    // The Xray core that would hold counters is never started on this path,
    // so there is nothing to ask it for. The kernel counts every packet
    // crossing the tunnel interface instead -- as payload rather than wire
    // bytes, which means the same thing the Xray counters mean, and excludes
    // this app's own calls to the control plane.
    readings = _poll(ref.watch(tunnelControllerProvider).readTunTraffic);
  } else {
    readings = ref.watch(xrayTunnelControllerProvider).traffic;
  }

  // Rebuilt whenever the session changes, because this watches
  // tunnelEstablishedAt: a reconnect is a new session, with its own baseline
  // and its own clock.
  final DevicesController controller = ref.read(
    devicesControllerProvider.notifier,
  );
  return _sessionScoped(
    readings,
    since: state.tunnelEstablishedAt,
    baseline: state.trafficBaseline,
    // Kept with the connection, so figures continue after the app's screen
    // is closed and reopened. Only for a session whose start this process saw.
    onBaseline:
        state.trafficBaseline == null && state.tunnelEstablishedAt != null
        ? (TunnelTraffic first) =>
              unawaited(controller.rememberTrafficBaseline(first))
        : null,
  );
});

/// Turns counters that may or may not reset into this session's figures.
///
/// The same problem the control plane has with server-side counters, and the
/// same answer: remember where this session started, report the difference.
///
/// It is needed because the backends disagree about resetting, and one of
/// them cannot be fixed from here -- the Xray plugin's manager is a
/// process-lifetime singleton whose totals and duration both survive a
/// disconnect, so a reconnected session opened showing the previous one's
/// bytes and a clock that had never stopped. Baselining is correct either
/// way: a counter that does reset simply has a baseline of zero.
///
/// Costs at most one interval of traffic at the start of a session, since the
/// first reading becomes the baseline rather than being reported.
Stream<TunnelTraffic?> _sessionScoped(
  Stream<TunnelTraffic> readings, {
  DateTime? since,
  TunnelTraffic? baseline,
  void Function(TunnelTraffic first)? onBaseline,
}) async* {
  // Clears whatever the previous session left on screen, before the first
  // reading of this one arrives.
  yield null;

  TunnelTraffic? start = baseline;
  await for (final TunnelTraffic reading in readings) {
    if (start == null) {
      start = reading;
      onBaseline?.call(reading);
    }
    yield TunnelTraffic(
      rxBytes: _sinceBaseline(reading.rxBytes, start.rxBytes),
      txBytes: _sinceBaseline(reading.txBytes, start.txBytes),
      // This clock rather than the backend's own, for the same reason the
      // bytes are baselined. Null when this process did not see the tunnel
      // come up, which is a real answer rather than a missing one.
      elapsed: since == null ? null : DateTime.now().difference(since),
    );
  }
}

/// How much of a reading belongs to this session.
///
/// A reading below the baseline means the counter reset underneath us -- the
/// engine restarted mid-session -- so the whole reading is new. Subtracting
/// would give a negative figure, which reads as a bug in the arithmetic
/// rather than in the counter it came from.
int _sinceBaseline(int reading, int baseline) =>
    reading >= baseline ? reading - baseline : reading;

Stream<TunnelTraffic> _poll(Future<TunnelTraffic?> Function() read) async* {
  // A first reading immediately, then on the interval. Waiting a whole tick
  // before the first one leaves the rows blank for a second on a screen that
  // has just said "Protected".
  while (true) {
    final TunnelTraffic? reading = await _read(read);
    if (reading != null) {
      yield reading;
    }
    await Future<void>.delayed(kTunnelTrafficInterval);
  }
}

Future<TunnelTraffic?> _read(Future<TunnelTraffic?> Function() read) async {
  try {
    return await read();
  } on Object {
    // A failed read is a gap in the series, not the end of it: the tunnel may
    // be mid-teardown, or the platform channel briefly unavailable during a
    // configuration change. Skipping the reading keeps the last good figure
    // on screen, which is closer to true than dropping it to zero.
    return null;
  }
}
