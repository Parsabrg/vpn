/// Choosing which tunnel to read, and making the figures belong to one session.
///
/// Two silent failures live here, both reported from a real phone before
/// being fixed. Picking the wrong source means the screen never updates,
/// which looks exactly like a tunnel carrying no traffic. Carrying figures
/// across a reconnect means a fresh session opens showing the last one's
/// numbers, which looks exactly like traffic that already happened.
library;

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/misc.dart' show Override;
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/tunnel/tunnel_traffic.dart';
import 'package:nebula_mobile/core/wireguard/tunnel_controller.dart';
import 'package:nebula_mobile/core/xray/xray_tunnel_controller.dart';
import 'package:nebula_mobile/features/connect/tunnel_traffic_provider.dart';
import 'package:nebula_mobile/features/devices/devices_controller.dart';
import 'package:nebula_mobile/features/devices/devices_state.dart';

import '../devices/fake_tunnel_controller.dart';
import '../devices/fake_xray_tunnel_controller.dart';

/// Serves one fixed state, standing in for the real controller.
class _StubDevicesController extends DevicesController {
  _StubDevicesController(this._state);

  final DevicesState _state;
  final List<TunnelTraffic> remembered = <TunnelTraffic>[];

  @override
  DevicesState build() => _state;

  @override
  Future<void> rememberTrafficBaseline(TunnelTraffic reading) async {
    remembered.add(reading);
  }
}

ProviderContainer _container({
  required DevicesState state,
  required FakeTunnelController wireguard,
  required FakeXrayTunnelController xray,
  _StubDevicesController? controller,
}) {
  final ProviderContainer container = ProviderContainer(
    overrides: <Override>[
      devicesControllerProvider.overrideWith(
        () => controller ?? _StubDevicesController(state),
      ),
      tunnelControllerProvider.overrideWithValue(wireguard),
      xrayTunnelControllerProvider.overrideWithValue(xray),
    ],
  );
  addTearDown(container.dispose);
  return container;
}

DevicesState _state({
  required bool tunnel,
  String? protocol,
  String? transport,
  DateTime? establishedAt,
  TunnelTraffic? baseline,
}) {
  return DevicesState(
    loadStatus: DevicesLoadStatus.loaded,
    tunnelEstablished: tunnel,
    tunnelEstablishedAt: establishedAt,
    trafficBaseline: baseline,
    activeProtocolCode: protocol,
    xrayClient: transport == null
        ? null
        : XrayClientResult(
            clientId: 'client-1',
            uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
            serverAddress: 'ams-1.example.test',
            port: 8443,
            sni: 'ams-1.example.test',
            transport: transport,
            transportSecurity: 'tls',
            adBlock: false,
          ),
  );
}

/// Every value the provider publishes, in order, nulls included.
List<TunnelTraffic?> _collect(ProviderContainer container) {
  final List<TunnelTraffic?> seen = <TunnelTraffic?>[];
  container.listen<AsyncValue<TunnelTraffic?>>(tunnelTrafficProvider, (
    AsyncValue<TunnelTraffic?>? previous,
    AsyncValue<TunnelTraffic?> next,
  ) {
    if (next.hasValue) {
      seen.add(next.value);
    }
  }, fireImmediately: true);
  return seen;
}

/// Waits for the first real reading, past the null that opens every session.
Future<List<TunnelTraffic?>> _settled(
  ProviderContainer container, {
  Duration wait = const Duration(milliseconds: 60),
}) async {
  final List<TunnelTraffic?> seen = _collect(container);
  await Future<void>.delayed(wait);
  return seen;
}

void main() {
  test('no tunnel publishes null, so nothing is left on screen', () async {
    final FakeTunnelController wireguard = FakeTunnelController();
    final ProviderContainer container = _container(
      state: _state(tunnel: false, protocol: wireguardProtocolCode),
      wireguard: wireguard,
      xray: FakeXrayTunnelController(),
    );

    final List<TunnelTraffic?> seen = await _settled(
      container,
      wait: const Duration(milliseconds: 20),
    );

    expect(seen, <TunnelTraffic?>[null]);
    expect(wireguard.readTrafficCalls, 0);
  });

  test('a session opens by clearing whatever the last one left', () async {
    // The reported bug: a reconnected session showed the previous session's
    // bytes, because a provider that stops emitting keeps its last value.
    final FakeTunnelController wireguard = FakeTunnelController()
      ..traffic = const TunnelTraffic(rxBytes: 500, txBytes: 100);
    final ProviderContainer container = _container(
      state: _state(tunnel: true, protocol: wireguardProtocolCode),
      wireguard: wireguard,
      xray: FakeXrayTunnelController(),
    );

    final List<TunnelTraffic?> seen = await _settled(container);

    expect(seen.first, isNull);
  });

  group('figures belong to the session, not to the counter', () {
    test('a counter that never resets still reports from zero', () async {
      // The Xray plugin's manager is a process-lifetime singleton: its totals
      // survive a disconnect, so without a baseline a new session opens
      // showing the previous one's traffic.
      final FakeXrayTunnelController xray = FakeXrayTunnelController();
      final ProviderContainer container = _container(
        state: _state(tunnel: true, protocol: 'vless-xhttp-tls'),
        wireguard: FakeTunnelController(),
        xray: xray,
      );

      final List<TunnelTraffic?> seen = _collect(container);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      // A session beginning on a counter already standing at 900 MB.
      xray.trafficController.add(
        const TunnelTraffic(rxBytes: 900000000, txBytes: 5000000),
      );
      await Future<void>.delayed(const Duration(milliseconds: 10));
      xray.trafficController.add(
        const TunnelTraffic(rxBytes: 900004096, txBytes: 5000512),
      );
      await Future<void>.delayed(const Duration(milliseconds: 20));

      final List<TunnelTraffic> readings = seen
          .whereType<TunnelTraffic>()
          .toList();
      expect(readings.first.rxBytes, 0);
      expect(readings.last.rxBytes, 4096);
      expect(readings.last.txBytes, 512);
    });

    test(
      'a counter that resets mid-session counts the whole reading',
      () async {
        // The engine restarted underneath us. Subtracting a baseline that no
        // longer applies would give a negative figure.
        final FakeXrayTunnelController xray = FakeXrayTunnelController();
        final ProviderContainer container = _container(
          state: _state(tunnel: true, protocol: 'vless-xhttp-tls'),
          wireguard: FakeTunnelController(),
          xray: xray,
        );

        final List<TunnelTraffic?> seen = _collect(container);
        await Future<void>.delayed(const Duration(milliseconds: 10));
        xray.trafficController.add(
          const TunnelTraffic(rxBytes: 5000, txBytes: 500),
        );
        await Future<void>.delayed(const Duration(milliseconds: 10));
        xray.trafficController.add(
          const TunnelTraffic(rxBytes: 80, txBytes: 8),
        );
        await Future<void>.delayed(const Duration(milliseconds: 20));

        expect(seen.whereType<TunnelTraffic>().last.rxBytes, 80);
      },
    );

    test(
      'the clock comes from when the tunnel came up, not the backend',
      () async {
        // The plugin's own duration is held by the same singleton and kept
        // counting across a reconnect.
        final FakeXrayTunnelController xray = FakeXrayTunnelController();
        final ProviderContainer container = _container(
          state: _state(
            tunnel: true,
            protocol: 'vless-xhttp-tls',
            establishedAt: DateTime.now().subtract(const Duration(minutes: 2)),
          ),
          wireguard: FakeTunnelController(),
          xray: xray,
        );

        final List<TunnelTraffic?> seen = _collect(container);
        await Future<void>.delayed(const Duration(milliseconds: 10));
        xray.trafficController.add(
          // A backend claiming four hours, from a session long finished.
          const TunnelTraffic(
            rxBytes: 10,
            txBytes: 2,
            elapsed: Duration(hours: 4),
          ),
        );
        await Future<void>.delayed(const Duration(milliseconds: 20));

        expect(seen.whereType<TunnelTraffic>().last.elapsed!.inMinutes, 2);
      },
    );

    test('a reopened session counts from the baseline it kept', () async {
      // The tunnel ran on while the app's screen was closed; the figures on
      // reopening continue rather than restarting at zero.
      final FakeXrayTunnelController xray = FakeXrayTunnelController();
      final ProviderContainer container = _container(
        state: _state(
          tunnel: true,
          protocol: 'vless-xhttp-tls',
          establishedAt: DateTime.now().subtract(const Duration(hours: 1)),
          baseline: const TunnelTraffic(rxBytes: 100, txBytes: 10),
        ),
        wireguard: FakeTunnelController(),
        xray: xray,
      );

      final List<TunnelTraffic?> seen = _collect(container);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      xray.trafficController.add(
        const TunnelTraffic(rxBytes: 5100, txBytes: 710),
      );
      await Future<void>.delayed(const Duration(milliseconds: 20));

      final TunnelTraffic last = seen.whereType<TunnelTraffic>().last;
      expect(last.rxBytes, 5000);
      expect(last.txBytes, 700);
      expect(last.elapsed!.inMinutes, 60);
    });

    test('a new session hands its first reading to be kept', () async {
      final FakeXrayTunnelController xray = FakeXrayTunnelController();
      final DevicesState state = _state(
        tunnel: true,
        protocol: 'vless-xhttp-tls',
        establishedAt: DateTime.now(),
      );
      final _StubDevicesController controller = _StubDevicesController(state);
      final ProviderContainer container = _container(
        state: state,
        wireguard: FakeTunnelController(),
        xray: xray,
        controller: controller,
      );

      _collect(container);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      xray.trafficController.add(const TunnelTraffic(rxBytes: 42, txBytes: 7));
      xray.trafficController.add(const TunnelTraffic(rxBytes: 99, txBytes: 9));
      await Future<void>.delayed(const Duration(milliseconds: 20));

      expect(controller.remembered, const <TunnelTraffic>[
        TunnelTraffic(rxBytes: 42, txBytes: 7),
      ]);
    });

    test('a session this process did not start reports no elapsed', () async {
      final FakeXrayTunnelController xray = FakeXrayTunnelController();
      final ProviderContainer container = _container(
        state: _state(tunnel: true, protocol: 'vless-xhttp-tls'),
        wireguard: FakeTunnelController(),
        xray: xray,
      );

      final List<TunnelTraffic?> seen = _collect(container);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      xray.trafficController.add(
        const TunnelTraffic(
          rxBytes: 1,
          txBytes: 1,
          elapsed: Duration(hours: 4),
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 20));

      expect(seen.whereType<TunnelTraffic>().last.elapsed, isNull);
    });
  });

  group('which source is read', () {
    test(
      'WireGuard is polled, because it reports nothing on its own',
      () async {
        final FakeTunnelController wireguard = FakeTunnelController()
          ..traffic = const TunnelTraffic(rxBytes: 2048, txBytes: 512);
        final ProviderContainer container = _container(
          state: _state(tunnel: true, protocol: wireguardProtocolCode),
          wireguard: wireguard,
          xray: FakeXrayTunnelController(),
        );

        await _settled(container);

        expect(wireguard.readTrafficCalls, greaterThan(0));
        expect(wireguard.readTunTrafficCalls, 0);
      },
    );

    test(
      'Hysteria is read from the VPN interface, not from an engine',
      () async {
        // Hysteria2 runs as a child process and the Xray core that would hold
        // counters is never started, so asking an engine returns a zero that is
        // the absence of a measurement rather than a measurement of nothing.
        final FakeTunnelController wireguard = FakeTunnelController()
          ..tunTraffic = const TunnelTraffic(
            rxBytes: 131447573,
            txBytes: 3415084,
          );
        final ProviderContainer container = _container(
          state: _state(
            tunnel: true,
            protocol: 'hysteria2',
            transport: 'hysteria',
          ),
          wireguard: wireguard,
          xray: FakeXrayTunnelController(),
        );

        await _settled(container);

        expect(wireguard.readTunTrafficCalls, greaterThan(0));
        expect(wireguard.readTrafficCalls, 0);
      },
    );

    test('VLESS is subscribed to, not caught by the Hysteria rule', () async {
      final FakeTunnelController wireguard = FakeTunnelController();
      final FakeXrayTunnelController xray = FakeXrayTunnelController();
      final ProviderContainer container = _container(
        state: _state(
          tunnel: true,
          protocol: 'vless-xhttp-tls',
          transport: 'xhttp',
        ),
        wireguard: wireguard,
        xray: xray,
      );

      final List<TunnelTraffic?> seen = _collect(container);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      xray.trafficController.add(const TunnelTraffic(rxBytes: 0, txBytes: 0));
      xray.trafficController.add(const TunnelTraffic(rxBytes: 77, txBytes: 7));
      await Future<void>.delayed(const Duration(milliseconds: 20));

      expect(seen.whereType<TunnelTraffic>().last.rxBytes, 77);
      expect(wireguard.readTunTrafficCalls, 0);
      expect(wireguard.readTrafficCalls, 0);
    });

    test('a failed read is a gap, not the end of the series', () async {
      final FakeTunnelController wireguard = FakeTunnelController()
        ..readTrafficError = StateError('channel unavailable');
      final ProviderContainer container = _container(
        state: _state(tunnel: true, protocol: wireguardProtocolCode),
        wireguard: wireguard,
        xray: FakeXrayTunnelController(),
      );

      final List<TunnelTraffic?> seen = await _settled(container);

      expect(seen.whereType<TunnelTraffic>(), isEmpty);
      expect(wireguard.readTrafficCalls, greaterThan(0));
    });
  });
}
