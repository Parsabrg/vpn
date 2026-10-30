import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/diagnostics/diagnostics_report.dart';
import 'package:nebula_mobile/core/diagnostics/leak_test.dart';

void main() {
  const LeakReport leaks = LeakReport(
    exitCountry: 'DE',
    exitAddress: '203.0.x.x',
    dns: DnsVerdict.clean,
    resolverNetwork: '94.140.x.x',
    ipv6: Ipv6Verdict.leaking,
    ipv6Country: 'IR',
  );

  test('a connected session with a leak test reads line by line', () {
    expect(
      diagnosticsReport(
        appVersion: '0.1.18',
        platform: 'android 14',
        connected: true,
        localProxy: false,
        server: 'Germany 01',
        protocol: 'vless-xhttp-tls',
        lastTestMs: 184,
        handshakeAge: const Duration(seconds: 12),
        leaks: leaks,
      ),
      'Nebula VPN 0.1.18 · android 14\n'
      'Status: connected\n'
      'Server: Germany 01\n'
      'Protocol: vless-xhttp-tls\n'
      'Last protocol test: 184 ms\n'
      'WireGuard handshake: 12 s ago\n'
      'Exit: DE · 203.0.x.x\n'
      'DNS: no forged answers\n'
      'Resolver network: 94.140.x.x\n'
      'IPv6: leaving in IR',
    );
  });

  test('without a session or a test it says only that', () {
    expect(
      diagnosticsReport(
        appVersion: '0.1.18',
        platform: 'windows 10.0',
        connected: false,
        localProxy: false,
      ),
      'Nebula VPN 0.1.18 · windows 10.0\nStatus: not connected',
    );
  });

  test('it has no field that could carry a credential or a full address', () {
    // The function's inputs are the whole of what can reach the report:
    // names, codes, numbers and the leak test's masked networks.
    final String report = diagnosticsReport(
      appVersion: '0.1.18',
      platform: 'linux',
      connected: true,
      localProxy: true,
      leaks: leaks,
    );
    expect(report, contains('local proxy'));
    expect(RegExp(r'\d+\.\d+\.\d+\.\d+').hasMatch(report), isFalse);
  });

  test('packet loss reads as lost of sent, with the delay', () {
    final String report = diagnosticsReport(
      appVersion: '0.1.22',
      platform: 'android 14',
      connected: true,
      localProxy: false,
      loss: (
        sent: 20,
        received: 19,
        median: const Duration(milliseconds: 84),
        jitter: const Duration(milliseconds: 6),
      ),
    );
    expect(report, contains('Packet loss: 1/20 (5%) · 84 ms, varies 6 ms'));
  });
}
