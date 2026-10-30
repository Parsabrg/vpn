import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

/// Finding a Cloudflare address that works from this network (roadmap 11).
///
/// The CDN route reaches the server through Cloudflare, which answers for
/// the route's name at any of its edge addresses. Networks in Iran throttle
/// or block some of those addresses and not others, and DNS hands out
/// whichever it hands out. This tries a sample of them from the device, the
/// way the tunnel would use them -- a TLS connection for the route's own
/// name -- and keeps the fastest that answered. The tunnel then dials that
/// address while TLS and the Host header keep the name.

/// Cloudflare's published IPv4 ranges (cloudflare.com/ips-v4).
const List<String> cloudflareIpv4Ranges = <String>[
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
];

int _ipv4(String ip) =>
    ip.split('.').map(int.parse).fold(0, (int v, int o) => (v << 8) | o);

String _dotted(int value) => <int>[
  value >> 24 & 255,
  value >> 16 & 255,
  value >> 8 & 255,
  value & 255,
].join('.');

/// Whether [ip] is one of Cloudflare's: only a route through Cloudflare
/// has edge addresses to choose between.
bool isCloudflareAddress(String ip) {
  final InternetAddress? address = InternetAddress.tryParse(ip);
  if (address == null || address.type != InternetAddressType.IPv4) {
    return false;
  }
  final int value = _ipv4(ip);
  return cloudflareIpv4Ranges.any((String range) {
    final List<String> parts = range.split('/');
    final int bits = int.parse(parts[1]);
    final int mask = bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF;
    return value & mask == _ipv4(parts[0]) & mask;
  });
}

/// [count] distinct addresses from Cloudflare's ranges, each range weighted
/// by its size so the large ones are not under-sampled. Never a network or
/// broadcast address.
List<String> sampleCloudflareAddresses(int count, {Random? random}) {
  final Random rng = random ?? Random.secure();
  final List<(int, int)> ranges = <(int, int)>[
    for (final String range in cloudflareIpv4Ranges)
      (_ipv4(range.split('/')[0]), 1 << (32 - int.parse(range.split('/')[1]))),
  ];
  final int total = ranges.fold(0, (int sum, (int, int) r) => sum + r.$2);
  final Set<String> picked = <String>{};
  while (picked.length < count) {
    int at = rng.nextInt(total);
    for (final (int start, int size) in ranges) {
      if (at < size) {
        final int value = start + at;
        if (value & 255 != 0 && value & 255 != 255) {
          picked.add(_dotted(value));
        }
        break;
      }
      at -= size;
    }
  }
  return picked.toList();
}

/// One address that answered, and how fast.
typedef CleanIpResult = ({String ip, int milliseconds});

/// Tries [candidates] for [host], [concurrency] at a time, and returns the
/// ones that answered, fastest first.
Future<List<CleanIpResult>> scanCleanIps(
  String host,
  List<String> candidates, {
  int concurrency = 16,
  Future<int?> Function(String ip, String host)? probe,
  void Function(int done)? onProgress,
}) async {
  final Future<int?> Function(String, String) test =
      probe ?? (String ip, String host) => probeNamed(ip, host);
  final List<CleanIpResult> found = <CleanIpResult>[];
  int next = 0;
  int done = 0;
  Future<void> worker() async {
    while (next < candidates.length) {
      final String ip = candidates[next++];
      final int? ms = await test(ip, host);
      if (ms != null) {
        found.add((ip: ip, milliseconds: ms));
      }
      onProgress?.call(++done);
    }
  }

  await Future.wait(<Future<void>>[
    for (int i = 0; i < concurrency; i++) worker(),
  ]);
  found.sort(
    (CleanIpResult a, CleanIpResult b) =>
        a.milliseconds.compareTo(b.milliseconds),
  );
  return found;
}

/// A TLS connection to [ip] for [host] -- SNI and certificate both [host]'s
/// -- and an HTTP request answered by Cloudflare's own trace page: the path
/// the tunnel takes, short of the tunnel.
Future<int?> probeNamed(
  String ip,
  String host, {
  Duration timeout = const Duration(seconds: 3),
}) async {
  final Stopwatch watch = Stopwatch()..start();
  Socket? raw;
  SecureSocket? tls;
  try {
    raw = await Socket.connect(ip, 443, timeout: timeout);
    tls = await SecureSocket.secure(raw, host: host).timeout(timeout);
    tls.write(
      'GET /cdn-cgi/trace HTTP/1.1\r\nHost: $host\r\n'
      'User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n',
    );
    // Connection: close, so the whole (small) answer arrives and ends.
    final String answer = await tls
        .cast<List<int>>()
        .transform(const Utf8Decoder(allowMalformed: true))
        .join()
        .timeout(timeout);
    return answer.startsWith('HTTP/1.1 200') && answer.contains('colo=')
        ? watch.elapsedMilliseconds
        : null;
  } on Object {
    return null;
  } finally {
    tls?.destroy();
    raw?.destroy();
  }
}
