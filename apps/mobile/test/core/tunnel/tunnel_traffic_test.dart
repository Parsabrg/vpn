import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/tunnel/tunnel_traffic.dart';

void main() {
  group('parseTunnelDuration', () {
    test('reads the backend\'s HH:MM:SS', () {
      expect(parseTunnelDuration('00:00:00'), Duration.zero);
      expect(
        parseTunnelDuration('01:02:03'),
        const Duration(hours: 1, minutes: 2, seconds: 3),
      );
    });

    test('reads a session longer than a day', () {
      // The backend keeps counting hours rather than rolling over, so a
      // tunnel left up over a weekend reports something like this.
      expect(
        parseTunnelDuration('51:30:00'),
        const Duration(hours: 51, minutes: 30),
      );
    });

    test('unreadable input is null, never zero', () {
      // A tunnel up for hours showing 0:00 because the format changed is
      // worse than showing nothing, and a reader cannot tell the two apart.
      expect(parseTunnelDuration(''), isNull);
      expect(parseTunnelDuration('12:34'), isNull);
      expect(parseTunnelDuration('ab:cd:ef'), isNull);
      expect(parseTunnelDuration('-1:00:00'), isNull);
    });
  });

  group('formatTunnelDuration', () {
    test('omits the hour until there is one', () {
      expect(formatTunnelDuration(const Duration(seconds: 7)), '0:07');
      expect(
        formatTunnelDuration(const Duration(minutes: 7, seconds: 4)),
        '7:04',
      );
    });

    test('pads minutes only once hours are shown', () {
      // "3:7:04" is not a time. Minutes become a fixed-width field exactly
      // when something sits to their left.
      expect(
        formatTunnelDuration(const Duration(hours: 3, minutes: 7, seconds: 4)),
        '3:07:04',
      );
    });

    test('hours keep counting past a day rather than wrapping', () {
      // 27:14:03, not 3:14:03 -- a tunnel up for more than a day is a real
      // state and wrapping would silently understate it by a day.
      expect(
        formatTunnelDuration(
          const Duration(hours: 27, minutes: 14, seconds: 3),
        ),
        '27:14:03',
      );
    });

    test('a negative duration never renders as a time', () {
      expect(formatTunnelDuration(const Duration(seconds: -5)), '0:00');
    });
  });

  group('TunnelTraffic', () {
    test('totals both directions', () {
      const TunnelTraffic traffic = TunnelTraffic(rxBytes: 300, txBytes: 40);
      expect(traffic.totalBytes, 340);
    });

    test('an unknown elapsed is null, not zero', () {
      // WireGuard reports bytes and not time. A clock starting at zero when
      // the screen opened would be a plausible number that is simply wrong.
      const TunnelTraffic traffic = TunnelTraffic(rxBytes: 1, txBytes: 2);
      expect(traffic.elapsed, isNull);
    });

    test('readings compare by value, so an unchanged one does not redraw', () {
      const TunnelTraffic first = TunnelTraffic(rxBytes: 1, txBytes: 2);
      const TunnelTraffic same = TunnelTraffic(rxBytes: 1, txBytes: 2);
      const TunnelTraffic moved = TunnelTraffic(rxBytes: 9, txBytes: 2);

      expect(first, same);
      expect(first, isNot(moved));
    });
  });
}
