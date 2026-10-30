import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// What this device's traffic and lookups look like from outside, right now.
///
/// Answers the questions a person asks when a VPN "says connected": where do
/// I appear to be, are my lookups answered by the VPN or by my network, and
/// does IPv6 go around it. Measured, not taken from the server list
/// (roadmap section 18: prefer measured truth over metadata).
///
/// Every address is shown masked: the screen may be shared to ask for help.
class LeakReport {
  const LeakReport({
    required this.exitCountry,
    required this.exitAddress,
    required this.dns,
    required this.resolverNetwork,
    required this.ipv6,
    required this.ipv6Country,
  });

  /// Two-letter country of the IPv4 exit; null when the test address
  /// could not be reached.
  final String? exitCountry;

  /// The IPv4 exit, masked.
  final String? exitAddress;

  final DnsVerdict dns;

  /// The network of the resolver that answered, masked; null when unknown.
  final String? resolverNetwork;

  final Ipv6Verdict ipv6;

  /// Country of the IPv6 exit when there is one.
  final String? ipv6Country;
}

enum DnsVerdict {
  /// Every probe name resolved to a public address.
  clean,

  /// A probe name resolved to a private or reserved address: the local
  /// network's resolver answered, which is the forging Iranian networks do,
  /// so the lookup went around the VPN.
  forged,

  /// No lookup answered at all.
  failed,
}

enum Ipv6Verdict {
  /// IPv6 does not get out: blocked by the tunnel, or no IPv6 here.
  unavailable,

  /// IPv6 gets out in the same country as IPv4.
  sameExit,

  /// IPv6 gets out somewhere else than IPv4 -- around the tunnel.
  leaking,
}

/// Names Iranian networks answer with forged, private addresses. Through
/// the VPN they resolve to their real, public ones.
const List<String> leakProbeNames = <String>[
  'facebook.com',
  'twitter.com',
  'instagram.com',
  'youtube.com',
];

typedef Lookup = Future<List<InternetAddress>> Function(String host);
typedef Fetch = Future<String?> Function(Uri url);

class LeakTest {
  LeakTest({Lookup? lookup, Fetch? fetch})
    : _lookup = lookup ?? InternetAddress.lookup,
      _fetch = fetch ?? _get;

  final Lookup _lookup;
  final Fetch _fetch;

  // Cloudflare's trace by address, so the exit is measured without DNS;
  // its certificate names these addresses.
  static final Uri _ipv4Trace = Uri.parse('https://1.1.1.1/cdn-cgi/trace');
  static final Uri _ipv6Trace = Uri.parse(
    'https://[2606:4700:4700::1111]/cdn-cgi/trace',
  );

  Future<LeakReport> run() async {
    final List<Object?> results = await Future.wait(<Future<Object?>>[
      _fetch(_ipv4Trace),
      _fetch(_ipv6Trace),
      _dnsVerdict(),
      _resolverNetwork(),
    ]);
    final Map<String, String> ipv4 = parseTrace(results[0] as String?);
    final Map<String, String> ipv6 = parseTrace(results[1] as String?);
    final String? v4Country = ipv4['loc'];
    final String? v6Country = ipv6['loc'];
    return LeakReport(
      exitCountry: v4Country,
      exitAddress: ipv4['ip'] == null ? null : maskAddress(ipv4['ip']!),
      dns: results[2]! as DnsVerdict,
      resolverNetwork: results[3] as String?,
      ipv6: v6Country == null
          ? Ipv6Verdict.unavailable
          : v6Country == v4Country
          ? Ipv6Verdict.sameExit
          : Ipv6Verdict.leaking,
      ipv6Country: v6Country,
    );
  }

  Future<DnsVerdict> _dnsVerdict() async {
    bool answered = false;
    for (final String name in leakProbeNames) {
      final List<InternetAddress> addresses = await _lookup(name)
          .timeout(const Duration(seconds: 8))
          .catchError((Object _) {
            return <InternetAddress>[];
          });
      if (addresses.isEmpty) {
        continue;
      }
      answered = true;
      if (addresses.any(isReservedAddress)) {
        return DnsVerdict.forged;
      }
    }
    return answered ? DnsVerdict.clean : DnsVerdict.failed;
  }

  /// Akamai answers `whoami.akamai.net` with the address of the resolver
  /// that asked it.
  Future<String?> _resolverNetwork() async {
    try {
      final List<InternetAddress> addresses = await _lookup(
        'whoami.akamai.net',
      ).timeout(const Duration(seconds: 8));
      return addresses.isEmpty ? null : maskAddress(addresses.first.address);
    } on Object {
      return null;
    }
  }

  static Future<String?> _get(Uri url) async {
    final HttpClient client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 8);
    try {
      final HttpClientResponse response = await (await client.getUrl(
        url,
      )).close().timeout(const Duration(seconds: 10));
      if (response.statusCode != 200) {
        return null;
      }
      return await response
          .transform(utf8.decoder)
          .join()
          .timeout(const Duration(seconds: 10));
    } on Object {
      return null;
    } finally {
      client.close(force: true);
    }
  }
}

/// Cloudflare's `key=value` trace lines.
Map<String, String> parseTrace(String? body) => <String, String>{
  for (final String line in const LineSplitter().convert(body ?? ''))
    if (line.contains('='))
      line.substring(0, line.indexOf('=')): line.substring(
        line.indexOf('=') + 1,
      ),
};

/// Private, loopback, link-local, carrier-grade NAT, unspecified: no public
/// name resolves there, so an answer in these ranges was made up locally.
bool isReservedAddress(InternetAddress address) {
  if (address.isLoopback || address.isLinkLocal) {
    return true;
  }
  final List<int> b = address.rawAddress;
  if (address.type == InternetAddressType.IPv4) {
    return b[0] == 0 ||
        b[0] == 10 ||
        (b[0] == 100 && b[1] >= 64 && b[1] < 128) ||
        (b[0] == 172 && b[1] >= 16 && b[1] < 32) ||
        (b[0] == 192 && b[1] == 168);
  }
  // fc00::/7 unique local, :: unspecified.
  return (b[0] & 0xfe) == 0xfc || b.every((int byte) => byte == 0);
}

/// The first half of an address: enough to tell networks apart, not enough
/// to identify a connection.
String maskAddress(String address) {
  if (address.contains(':')) {
    final List<String> groups = address.split(':');
    return '${groups.take(2).join(':')}:…';
  }
  final List<String> parts = address.split('.');
  return parts.length == 4 ? '${parts[0]}.${parts[1]}.x.x' : address;
}
