import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import '../xray/local_proxy.dart';

/// How many of [LossReport.sent] small UDP packets came back, and how long
/// the answers took.
typedef LossReport = ({
  int sent,
  int received,
  Duration? median,
  Duration? jitter,
});

/// Real packet loss, measured the only way an app can without raw sockets:
/// one UDP DNS query out and one answer back per probe, so a probe with no
/// answer is a packet lost one way or the other. TCP would hide loss by
/// resending. Each query asks for a random name, so no cache along the way
/// can answer it -- every reply crossed the whole path, through the tunnel
/// when one is up.
class PacketLossTest {
  PacketLossTest({
    InternetAddress? target,
    this.port = 53,
    this.count = 20,
    this.spacing = const Duration(milliseconds: 100),
    this.wait = const Duration(seconds: 2),
    this.through,
    Random? random,
  }) : target = target ?? InternetAddress('1.1.1.1'),
       _random = random ?? Random.secure();

  final InternetAddress target;
  final int port;
  final int count;
  final Duration spacing;

  /// How long after the last probe a late answer still counts.
  final Duration wait;

  /// The tunnel's local proxy, where this app's own packets do not take the
  /// tunnel's path on their own (Android, which keeps the app out of its own
  /// VPN): they then go the way every app's UDP does. Sent straight from
  /// here, they measured the bare line while the screen said "through the
  /// VPN".
  final LocalProxy? through;
  final Random _random;

  Future<LossReport> run() async {
    final LocalProxy? proxy = through;
    final SocksUdp? relay = proxy == null ? null : await _open(proxy);
    if (proxy != null && relay == null) {
      // The tunnel's UDP could not be reached: nothing was sent through it.
      return (sent: 0, received: 0, median: null, jitter: null);
    }
    final RawDatagramSocket? socket = relay != null
        ? null
        : await RawDatagramSocket.bind(
            target.type == InternetAddressType.IPv6
                ? InternetAddress.anyIPv6
                : InternetAddress.anyIPv4,
            0,
          );
    final Map<int, Stopwatch> pending = <int, Stopwatch>{};
    final List<Duration> times = <Duration>[];
    void answered(Uint8List data) {
      if (data.length < 2) {
        return;
      }
      final Stopwatch? clock = pending.remove((data[0] << 8) | data[1]);
      if (clock != null) {
        times.add(clock.elapsed);
      }
    }

    final StreamSubscription<Object?> answers = relay != null
        ? relay.payloads.listen(answered)
        : socket!.listen((RawSocketEvent event) {
            if (event == RawSocketEvent.read) {
              final Datagram? datagram = socket.receive();
              if (datagram != null) {
                answered(datagram.data);
              }
            }
          });
    int sent = 0;
    try {
      for (int probe = 0; probe < count; probe++) {
        int id;
        do {
          id = _random.nextInt(0x10000);
        } while (pending.containsKey(id));
        pending[id] = Stopwatch()..start();
        if (relay != null) {
          relay.send(target, port, _query(id));
          sent++;
        } else if (socket!.send(_query(id), target, port) > 0) {
          sent++;
        } else {
          pending.remove(id);
        }
        await Future<void>.delayed(spacing);
      }
      await Future<void>.delayed(wait);
    } finally {
      await answers.cancel();
      socket?.close();
      relay?.close();
    }
    return (
      sent: sent,
      received: times.length,
      median: _median(times),
      jitter: _jitter(times),
    );
  }

  static Future<SocksUdp?> _open(LocalProxy proxy) async {
    try {
      return await SocksUdp.open(proxy);
    } on Object {
      return null;
    }
  }

  /// An A query for `<random>.cloudflare.com`, recursion desired.
  Uint8List _query(int id) {
    final String label = List<String>.generate(
      12,
      (_) => 'abcdefghijklmnopqrstuvwxyz0123456789'[_random.nextInt(36)],
    ).join();
    final BytesBuilder bytes = BytesBuilder()
      ..add(<int>[id >> 8, id & 0xff, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for (final String part in <String>[label, 'cloudflare', 'com']) {
      bytes
        ..addByte(part.length)
        ..add(part.codeUnits);
    }
    bytes.add(<int>[0, 0, 1, 0, 1]);
    return bytes.toBytes();
  }

  static Duration? _median(List<Duration> times) {
    if (times.isEmpty) {
      return null;
    }
    final List<Duration> sorted = List<Duration>.of(times)..sort();
    return sorted[sorted.length ~/ 2];
  }

  /// Mean difference between consecutive answers' times, as RFC 3550 means
  /// it loosely: how much the delay wobbles, not how long it is.
  static Duration? _jitter(List<Duration> times) {
    if (times.length < 2) {
      return null;
    }
    int total = 0;
    for (int i = 1; i < times.length; i++) {
      total += (times[i] - times[i - 1]).inMicroseconds.abs();
    }
    return Duration(microseconds: total ~/ (times.length - 1));
  }
}

/// Whole percent lost; null when nothing could be sent.
int? lossPercent(LossReport report) => report.sent == 0
    ? null
    : ((report.sent - report.received) * 100 / report.sent).round();
