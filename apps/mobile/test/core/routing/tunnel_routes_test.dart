/// The route list the tunnel claims.
///
/// This is arithmetic with a silent failure mode in both directions: a list
/// covering one address more than intended claims something meant to stay
/// local, and one address less leaves a hole in the tunnel that nothing
/// reports. So the tests check membership of specific addresses rather than
/// comparing against a expected list of blocks -- an expected list would only
/// prove the code agrees with whatever it produced the day it was written.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/routing/tunnel_routes.dart';

/// Whether [address] falls inside any of [cidrs].
bool _covers(List<String> cidrs, String address) {
  final int target = _toInt(address);
  for (final String cidr in cidrs) {
    final int slash = cidr.indexOf('/');
    final int base = _toInt(cidr.substring(0, slash));
    final int prefix = int.parse(cidr.substring(slash + 1));
    final int size = 1 << (32 - prefix);
    if (target >= base && target < base + size) {
      return true;
    }
  }
  return false;
}

int _toInt(String dotted) {
  int value = 0;
  for (final String part in dotted.split('.')) {
    value = (value << 8) | int.parse(part);
  }
  return value;
}

void main() {
  group('claiming everything', () {
    test('is a single route, not a computed list', () {
      // The default, and the only setting with nothing outside the tunnel.
      // Enumerating blocks here would be a longer way to say 0.0.0.0/0 and a
      // place for an arithmetic slip to hide.
      expect(tunnelRoutes(bypassLocalNetwork: false), <String>[
        '0.0.0.0/0',
        '::/0',
      ]);
    });

    test('IPv6 is claimed in both modes', () {
      // Not carried -- nothing downstream forwards it -- but claimed, because
      // leaving it unclaimed on an IPv6 network leaks the real address to
      // every host that supports it while the app still reports connected.
      expect(tunnelRoutes(bypassLocalNetwork: false), contains('::/0'));
      expect(tunnelRoutes(bypassLocalNetwork: true), contains('::/0'));
    });
  });

  group('bypassing the local network', () {
    final List<String> routes = ipv4RoutesExcluding(kLocalRanges);

    test('does not claim the private ranges', () {
      // The point of the mode: a printer, a NAS, a router admin page stay
      // reachable while the tunnel is up.
      for (final String local in <String>[
        '10.0.0.1',
        '10.255.255.255',
        '172.16.0.1',
        '172.31.255.255',
        '192.168.0.1',
        '192.168.1.254',
        '169.254.1.1',
        '127.0.0.1',
      ]) {
        expect(
          _covers(routes, local),
          isFalse,
          reason: '$local should stay on the local network',
        );
      }
    });

    test('still claims every public address', () {
      // The failure that matters. A slip here leaves real traffic outside the
      // tunnel, on a connection that reports itself as protected.
      for (final String public in <String>[
        '1.1.1.1',
        '8.8.8.8',
        '9.9.9.9',
        '11.0.0.1', // immediately above 10/8
        '172.15.255.255', // immediately below 172.16/12
        '172.32.0.0', // immediately above 172.16/12
        '192.167.255.255', // immediately below 192.168/16
        '192.169.0.0', // immediately above 192.168/16
        '169.253.255.255',
        '169.255.0.0',
        '126.255.255.255',
        '128.0.0.0',
        '223.255.255.255', // immediately below multicast
      ]) {
        expect(
          _covers(routes, public),
          isTrue,
          reason: '$public must go through the tunnel',
        );
      }
    });

    test('leaves multicast and the reserved top of the space alone', () {
      // A tunnel claiming these breaks local discovery -- casting to a TV,
      // finding a printer -- without carrying the traffic anywhere useful.
      expect(_covers(routes, '224.0.0.1'), isFalse);
      expect(_covers(routes, '239.255.255.250'), isFalse);
      expect(_covers(routes, '255.255.255.255'), isFalse);
    });

    test('produces valid, aligned CIDR blocks', () {
      // An unaligned block is one addRoute rejects, and the rejection
      // arrives as a failed connect with nothing naming the cause.
      for (final String cidr in routes) {
        final int slash = cidr.indexOf('/');
        final int base = _toInt(cidr.substring(0, slash));
        final int prefix = int.parse(cidr.substring(slash + 1));
        expect(prefix, inInclusiveRange(0, 32));
        expect(
          base % (1 << (32 - prefix)),
          0,
          reason: '$cidr is not aligned on its own boundary',
        );
      }
    });

    test('the blocks do not overlap', () {
      // Overlapping routes are not an error, but they are a sign the
      // subtraction produced spans it should have merged, and a list that is
      // longer than it needs to be is a list somebody will later mistrust.
      final List<List<int>> spans = routes.map((String cidr) {
        final int slash = cidr.indexOf('/');
        final int base = _toInt(cidr.substring(0, slash));
        final int size = 1 << (32 - int.parse(cidr.substring(slash + 1)));
        return <int>[base, base + size - 1];
      }).toList()..sort((List<int> a, List<int> b) => a[0].compareTo(b[0]));

      for (int index = 1; index < spans.length; index++) {
        expect(spans[index][0], greaterThan(spans[index - 1][1]));
      }
    });
  });

  group('the arithmetic itself', () {
    test('excluding nothing claims the whole space in one block', () {
      expect(ipv4RoutesExcluding(<String>[]), <String>['0.0.0.0/0']);
    });

    test('excluding everything claims nothing', () {
      // Not a route list of zero-length blocks, and not 0.0.0.0/0 either.
      expect(ipv4RoutesExcluding(<String>['0.0.0.0/0']), isEmpty);
    });

    test('a hole in the middle splits the space in two', () {
      final List<String> routes = ipv4RoutesExcluding(<String>['128.0.0.0/1']);

      expect(routes, <String>['0.0.0.0/1']);
    });

    test('a sloppily written CIDR is masked to its block', () {
      // 10.1.2.3/8 describes 10.0.0.0/8. Treating the address as the start of
      // the span instead would leave 10.0.0.0 to 10.1.2.2 excluded from
      // nothing and claimed by neither list.
      expect(
        ipv4RoutesExcluding(<String>['10.1.2.3/8']),
        ipv4RoutesExcluding(<String>['10.0.0.0/8']),
      );
    });

    test('a single address can be excluded', () {
      final List<String> routes = ipv4RoutesExcluding(<String>['1.2.3.4/32']);

      expect(_covers(routes, '1.2.3.4'), isFalse);
      expect(_covers(routes, '1.2.3.3'), isTrue);
      expect(_covers(routes, '1.2.3.5'), isTrue);
    });

    test('overlapping exclusions are handled without duplicating routes', () {
      final List<String> routes = ipv4RoutesExcluding(<String>[
        '10.0.0.0/8',
        '10.1.0.0/16',
      ]);

      expect(routes, ipv4RoutesExcluding(<String>['10.0.0.0/8']));
    });

    test('a malformed CIDR is rejected rather than silently skipped', () {
      // Skipping it would quietly claim a range meant to stay local.
      expect(
        () => ipv4RoutesExcluding(<String>['10.0.0.0']),
        throwsArgumentError,
      );
      expect(
        () => ipv4RoutesExcluding(<String>['10.0.0.0/33']),
        throwsArgumentError,
      );
      expect(
        () => ipv4RoutesExcluding(<String>['10.0.0/8']),
        throwsArgumentError,
      );
      expect(
        () => ipv4RoutesExcluding(<String>['10.0.0.256/8']),
        throwsArgumentError,
      );
    });
  });
}
