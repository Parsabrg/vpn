/// Which addresses the tunnel claims.
///
/// A VpnService captures traffic by *claiming routes*, and before API 33 there
/// is no way to exclude one -- you can only enumerate what you take. So
/// "bypass the local network" is not a subtraction the platform performs; it
/// is a route list that covers everything except those ranges, which is what
/// this computes.
///
/// Worth being explicit about a trap here. The backend parameter that carries
/// this is called `bypassSubnets`, and its own documentation says it is a list
/// of "subnets to bypass the VPN". It is not: the native service passes each
/// entry straight to `VpnService.Builder.addRoute`, so every subnet listed is
/// one the tunnel *takes*. Reading the name rather than the implementation
/// would produce a build that routes the LAN through the tunnel and leaves the
/// internet direct -- the exact opposite, and one that still looks connected.
///
/// The list is computed rather than pasted. Every other client ships a
/// hand-written table of the complement of the private ranges; a table is a
/// thing that can be subtly wrong in a way nothing detects, while the
/// arithmetic can be tested against the ranges it is meant to exclude.
library;

/// Addresses that are never somewhere on the internet, and so are the ones
/// worth leaving on the local network when somebody asks for that.
///
/// Loopback is included for completeness rather than necessity -- Android
/// refuses to route it into a tunnel anyway -- and multicast and the broadcast
/// address because a tunnel claiming them breaks local discovery (casting to a
/// TV, finding a printer) without carrying the traffic anywhere useful.
const List<String> kLocalRanges = <String>[
  '0.0.0.0/8', // "this network"
  '10.0.0.0/8', // RFC 1918
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local
  '172.16.0.0/12', // RFC 1918
  '192.168.0.0/16', // RFC 1918
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, includes the broadcast address
];

/// Everything, which is the default and the only setting that leaves nothing
/// outside the tunnel.
const List<String> kAllIPv4 = <String>['0.0.0.0/0'];

/// IPv6 is claimed but not carried.
///
/// Nothing downstream forwards it -- tun2socks is started with IPv4 netif
/// arguments only -- so these packets enter the tunnel and are dropped. That
/// is the intent: on an IPv6-capable network, *not* claiming it leaks the real
/// address to every host that supports it while the app still reports
/// connected. Clients see IPv6 as unreachable and fall back to IPv4 over the
/// tunnel, which is what keeps the address hidden.
const String kIPv6Everything = '::/0';

class _Span {
  const _Span(this.start, this.end);

  /// Inclusive, as 32-bit unsigned values held in Dart's 64-bit ints, so
  /// `end + 1` on the top of the space cannot overflow into nonsense.
  final int start;
  final int end;
}

/// The routes to claim, given whether the local network should stay outside.
List<String> tunnelRoutes({required bool bypassLocalNetwork}) {
  final List<String> ipv4 = bypassLocalNetwork
      ? ipv4RoutesExcluding(kLocalRanges)
      : kAllIPv4;
  return <String>[...ipv4, kIPv6Everything];
}

/// The whole IPv4 space with [excluded] removed, as a minimal CIDR list.
List<String> ipv4RoutesExcluding(List<String> excluded) {
  List<_Span> remaining = <_Span>[const _Span(0, 0xFFFFFFFF)];
  for (final String cidr in excluded) {
    final _Span hole = _parseCidr(cidr);
    remaining = remaining
        .expand((_Span span) => _subtract(span, hole))
        .toList(growable: false);
  }
  return remaining
      .expand((_Span span) => _cidrsSpanning(span.start, span.end))
      .toList(growable: false);
}

_Span _parseCidr(String cidr) {
  final int slash = cidr.indexOf('/');
  if (slash < 0) {
    throw ArgumentError.value(cidr, 'cidr', 'must be address/prefix');
  }
  final int address = _parseAddress(cidr.substring(0, slash));
  final int prefix = int.parse(cidr.substring(slash + 1));
  if (prefix < 0 || prefix > 32) {
    throw ArgumentError.value(cidr, 'cidr', 'prefix must be 0..32');
  }
  final int size = _blockSize(prefix);
  // Masked, so a sloppily written 10.1.2.3/8 still describes 10.0.0.0/8
  // rather than a span that starts partway into the block.
  final int base = address & _maskFor(prefix);
  return _Span(base, base + size - 1);
}

int _parseAddress(String dotted) {
  final List<String> parts = dotted.split('.');
  if (parts.length != 4) {
    throw ArgumentError.value(dotted, 'address', 'must have four octets');
  }
  int value = 0;
  for (final String part in parts) {
    final int octet = int.parse(part);
    if (octet < 0 || octet > 255) {
      throw ArgumentError.value(dotted, 'address', 'octets must be 0..255');
    }
    value = (value << 8) | octet;
  }
  return value;
}

int _blockSize(int prefix) => 1 << (32 - prefix);

int _maskFor(int prefix) {
  if (prefix == 0) {
    return 0;
  }
  return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
}

/// [span] with [hole] removed: nothing, the span itself, or one or two pieces.
List<_Span> _subtract(_Span span, _Span hole) {
  if (hole.end < span.start || hole.start > span.end) {
    return <_Span>[span];
  }
  final List<_Span> pieces = <_Span>[];
  if (hole.start > span.start) {
    pieces.add(_Span(span.start, hole.start - 1));
  }
  if (hole.end < span.end) {
    pieces.add(_Span(hole.end + 1, span.end));
  }
  return pieces;
}

/// The fewest CIDR blocks that exactly cover [start]..[end].
///
/// Exactly: a route list that covered one address more than intended would
/// claim something meant to stay local, and one address less would leave a
/// hole in the tunnel. Both are silent.
List<String> _cidrsSpanning(int start, int end) {
  final List<String> blocks = <String>[];
  int current = start;
  while (current <= end) {
    // Grow the block while it stays aligned on its own boundary and still
    // fits inside what is left.
    int prefix = 32;
    while (prefix > 0) {
      final int candidate = prefix - 1;
      final int size = _blockSize(candidate);
      if (current % size != 0 || current + size - 1 > end) {
        break;
      }
      prefix = candidate;
    }
    blocks.add('${_toDotted(current)}/$prefix');
    current += _blockSize(prefix);
  }
  return blocks;
}

String _toDotted(int value) {
  return '${(value >> 24) & 0xFF}.${(value >> 16) & 0xFF}'
      '.${(value >> 8) & 0xFF}.${value & 0xFF}';
}
