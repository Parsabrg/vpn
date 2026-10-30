import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/diagnostics/leak_test.dart';

void main() {
  String trace(String ip, String loc) => 'fl=1\nip=$ip\nloc=$loc\nwarp=off\n';

  LeakTest probe({
    required Map<String, List<String>> dns,
    String? ipv4Trace,
    String? ipv6Trace,
  }) => LeakTest(
    lookup: (String host) async => <InternetAddress>[
      for (final String a in dns[host] ?? const <String>[]) InternetAddress(a),
    ],
    fetch: (Uri url) async => url.host.contains(':') ? ipv6Trace : ipv4Trace,
  );

  test('through the VPN: exit measured, real answers, no IPv6', () async {
    final LeakReport report = await probe(
      dns: <String, List<String>>{
        for (final String name in leakProbeNames)
          name: <String>['157.240.1.35'],
        'whoami.akamai.net': <String>['94.140.14.140'],
      },
      ipv4Trace: trace('203.0.113.2', 'DE'),
    ).run();
    expect(report.exitCountry, 'DE');
    expect(report.exitAddress, '203.0.x.x');
    expect(report.dns, DnsVerdict.clean);
    expect(report.resolverNetwork, '94.140.x.x');
    expect(report.ipv6, Ipv6Verdict.unavailable);
  });

  test("a forged answer from the network's resolver is a leak", () async {
    final LeakReport report = await probe(
      dns: <String, List<String>>{
        'facebook.com': <String>['157.240.1.35'],
        'twitter.com': <String>['10.10.34.36'],
      },
      ipv4Trace: trace('203.0.113.2', 'DE'),
    ).run();
    expect(report.dns, DnsVerdict.forged);
  });

  test('no answers at all is a failure, not a pass', () async {
    final LeakReport report = await probe(dns: <String, List<String>>{}).run();
    expect(report.dns, DnsVerdict.failed);
    expect(report.exitCountry, isNull);
  });

  test(
    'IPv6 leaving in another country leaks; the same country does not',
    () async {
      final Map<String, List<String>> dns = <String, List<String>>{
        'facebook.com': <String>['157.240.1.35'],
      };
      final LeakReport leak = await probe(
        dns: dns,
        ipv4Trace: trace('203.0.113.2', 'DE'),
        ipv6Trace: trace('2001:db8::1', 'IR'),
      ).run();
      expect(leak.ipv6, Ipv6Verdict.leaking);
      expect(leak.ipv6Country, 'IR');
      final LeakReport same = await probe(
        dns: dns,
        ipv4Trace: trace('203.0.113.2', 'DE'),
        ipv6Trace: trace('2001:db8::1', 'DE'),
      ).run();
      expect(same.ipv6, Ipv6Verdict.sameExit);
    },
  );

  test('reserved addresses are the ones no public name resolves to', () {
    for (final String a in <String>[
      '10.10.34.35',
      '127.0.0.1',
      '0.0.0.0',
      '100.64.0.1',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.1.1',
      'fd00::1',
      '::',
    ]) {
      expect(isReservedAddress(InternetAddress(a)), isTrue, reason: a);
    }
    for (final String a in <String>['8.8.8.8', '172.32.0.1', '2606:4700::1']) {
      expect(isReservedAddress(InternetAddress(a)), isFalse, reason: a);
    }
  });

  test('addresses are masked to their network', () {
    expect(maskAddress('203.0.113.46'), '203.0.x.x');
    expect(maskAddress('2001:db8:c0c:1::2'), '2001:db8:…');
  });
}
