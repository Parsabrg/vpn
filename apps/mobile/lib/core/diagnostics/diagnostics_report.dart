import 'leak_test.dart';
import 'packet_loss.dart';
import 'speed_test.dart';

/// The text "Copy report" puts on the clipboard, for asking for help.
///
/// Roadmap section 78: what is wrong, never what could be used. It names
/// the app, the platform, the server's display name, the protocol and the
/// measurements, with every address cut to its network. It never holds keys,
/// tokens, passwords, UUIDs, full configs, full addresses or anything
/// visited. English on purpose: it is read by whoever helps, not the person
/// holding the phone.
String diagnosticsReport({
  required String appVersion,
  required String platform,
  required bool connected,
  required bool localProxy,
  String? server,
  String? protocol,
  int? lastTestMs,
  Duration? handshakeAge,
  LeakReport? leaks,
  SpeedReport? speed,
  LossReport? loss,
}) {
  final List<String> lines = <String>[
    'Nebula VPN $appVersion · $platform',
    'Status: ${connected ? 'connected' : 'not connected'}'
        '${localProxy ? ' · local proxy' : ''}',
    if (server != null) 'Server: $server',
    if (protocol != null) 'Protocol: $protocol',
    if (lastTestMs != null) 'Last protocol test: $lastTestMs ms',
    if (handshakeAge != null)
      'WireGuard handshake: ${handshakeAge.inSeconds} s ago',
  ];
  if (leaks != null) {
    lines.addAll(<String>[
      'Exit: ${leaks.exitCountry == null ? 'unreachable' : '${leaks.exitCountry} · ${leaks.exitAddress}'}',
      'DNS: ${switch (leaks.dns) {
        DnsVerdict.clean => 'no forged answers',
        DnsVerdict.forged => 'forged by the network',
        DnsVerdict.failed => 'lookups failed',
      }}',
      if (leaks.resolverNetwork != null)
        'Resolver network: ${leaks.resolverNetwork}',
      'IPv6: ${switch (leaks.ipv6) {
        Ipv6Verdict.unavailable => 'blocked or unavailable',
        Ipv6Verdict.sameExit => 'same exit as IPv4',
        Ipv6Verdict.leaking => 'leaving in ${leaks.ipv6Country}',
      }}',
    ]);
  }
  if (speed != null) {
    String shown(double? mbps) =>
        mbps == null ? 'not measured' : '${formatMbps(mbps)} Mbps';
    lines.add(
      'Speed: ${shown(speed.downloadMbps)} down · '
      '${shown(speed.uploadMbps)} up',
    );
  }
  if (loss != null) {
    final int? percent = lossPercent(loss);
    final Duration? median = loss.median;
    lines.add(
      percent == null
          ? 'Packet loss: could not send'
          : 'Packet loss: ${loss.sent - loss.received}/${loss.sent} ($percent%)'
                '${median == null ? '' : ' · ${median.inMilliseconds} ms, varies ${loss.jitter?.inMilliseconds ?? 0} ms'}',
    );
  }
  return lines.join('\n');
}
