/// A session picked back up by a reopened app keeps its clock and figures.
///
/// Reported from the phone: closing the app's screen and opening it again,
/// with the tunnel up the whole time, showed no session time and counters
/// back at zero -- which read as the connection having dropped and started
/// over. The screen's state had been rebuilt; the tunnel had not.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/connection_record_store.dart';
import 'package:nebula_mobile/core/tunnel/tunnel_traffic.dart';
import 'package:nebula_mobile/features/devices/devices_controller.dart';

final DateTime _now = DateTime(2026, 9, 17, 14, 30);

ConnectionRecord _record({DateTime? establishedAt, TunnelTraffic? baseline}) {
  return ConnectionRecord(
    serverCode: 'ams-2',
    profileCode: 'vless-xhttp-tls',
    protocolCode: 'vless',
    sanctionsOnly: false,
    xrayClient: const XrayClientResult(
      clientId: 'client-1',
      uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
      serverAddress: 'ams-2.example.test',
      port: 443,
      sni: 'ams-2.example.test',
      transport: 'xhttp',
      transportSecurity: 'tls',
      adBlock: false,
    ),
    establishedAt: establishedAt,
    trafficBaseline: baseline,
  );
}

void main() {
  group('adoptedSession', () {
    test('the recorded start and baseline stand while the tunnel ran on', () {
      final DateTime started = _now.subtract(const Duration(hours: 2));
      const TunnelTraffic baseline = TunnelTraffic(rxBytes: 700, txBytes: 90);

      final AdoptedSession session = adoptedSession(
        _record(establishedAt: started, baseline: baseline),
        restoredAt: null,
        now: _now,
      );

      expect(session.since, started);
      expect(session.baseline, baseline);
    });

    test('a restore since the record started the session again', () {
      // After a phone restart or an app update Android brings the tunnel back
      // itself: a new session, with the engine's counters at zero.
      final DateTime restored = _now.subtract(const Duration(minutes: 5));

      final AdoptedSession session = adoptedSession(
        _record(
          establishedAt: _now.subtract(const Duration(days: 1)),
          baseline: const TunnelTraffic(rxBytes: 700, txBytes: 90),
        ),
        restoredAt: restored,
        now: _now,
      );

      expect(session.since, restored);
      expect(session.baseline, const TunnelTraffic(rxBytes: 0, txBytes: 0));
    });

    test('a restore older than the record belongs to an earlier session', () {
      final DateTime started = _now.subtract(const Duration(minutes: 10));

      final AdoptedSession session = adoptedSession(
        _record(establishedAt: started),
        restoredAt: _now.subtract(const Duration(days: 2)),
        now: _now,
      );

      expect(session.since, started);
    });

    test('a record from before this existed has no clock to give', () {
      final AdoptedSession session = adoptedSession(
        _record(),
        restoredAt: null,
        now: _now,
      );

      expect(session.since, isNull);
      expect(session.baseline, isNull);
    });

    test('a start in the future is a clock that moved, and unknown', () {
      final AdoptedSession session = adoptedSession(
        _record(establishedAt: _now.add(const Duration(hours: 1))),
        restoredAt: null,
        now: _now,
      );

      expect(session.since, isNull);
    });
  });

  group('the record', () {
    test('keeps the start and baseline through JSON', () {
      final DateTime started = DateTime.fromMillisecondsSinceEpoch(
        1789640000000,
      );
      final ConnectionRecord? restored = ConnectionRecord.fromJson(
        _record(establishedAt: started)
            .withTrafficBaseline(const TunnelTraffic(rxBytes: 5, txBytes: 6))
            .toJson(),
      );

      expect(restored?.establishedAt, started);
      expect(
        restored?.trafficBaseline,
        const TunnelTraffic(rxBytes: 5, txBytes: 6),
      );
    });

    test('a record written before these fields is still a record', () {
      final Map<String, Object?> json = _record().toJson()
        ..remove('establishedAtMs');

      final ConnectionRecord? restored = ConnectionRecord.fromJson(json);

      expect(restored, isNotNull);
      expect(restored?.establishedAt, isNull);
      expect(restored?.trafficBaseline, isNull);
    });
  });
}
