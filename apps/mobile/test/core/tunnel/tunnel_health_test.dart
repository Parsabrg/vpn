import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/tunnel/tunnel_health.dart';

void main() {
  final DateTime now = DateTime.utc(2026, 9, 24, 12);

  group('wireguardHealth', () {
    test('a handshake inside the session limit is alive', () {
      expect(
        wireguardHealth(now.subtract(const Duration(minutes: 2)), now),
        EngineHealth.alive,
      );
    });

    test('no rekey for longer than WireGuard allows is dead', () {
      expect(
        wireguardHealth(now.subtract(const Duration(minutes: 4)), now),
        EngineHealth.dead,
      );
    });

    test('never having completed a handshake is dead', () {
      expect(
        wireguardHealth(DateTime.fromMillisecondsSinceEpoch(0), now),
        EngineHealth.dead,
      );
    });

    test('not knowing is never a verdict', () {
      expect(wireguardHealth(null, now), EngineHealth.unknown);
    });
  });

  test('engineProcessHealth maps running, stopped and unknown', () {
    expect(engineProcessHealth(true), EngineHealth.alive);
    expect(engineProcessHealth(false), EngineHealth.dead);
    expect(engineProcessHealth(null), EngineHealth.unknown);
  });

  group('parseLatestHandshakes', () {
    test('takes the newest handshake across peers', () {
      final DateTime? latest = parseLatestHandshakes(
        'AAAA=\t1790000000\nBBBB=\t1790000100\n',
      );

      expect(
        latest,
        DateTime.fromMillisecondsSinceEpoch(1790000100 * 1000, isUtc: true),
      );
    });

    test('a peer that never shook hands reads as the epoch', () {
      expect(parseLatestHandshakes('AAAA=\t0\r\n')!.millisecondsSinceEpoch, 0);
    });

    test('no peers is not an answer', () {
      expect(parseLatestHandshakes(''), isNull);
      expect(parseLatestHandshakes('Unable to access interface\n'), isNull);
    });
  });
}
