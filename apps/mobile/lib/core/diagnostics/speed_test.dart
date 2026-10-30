import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// Megabits per second each way; null where it could not be measured.
typedef SpeedReport = ({double? downloadMbps, double? uploadMbps});

/// How fast this app's traffic moves: through the tunnel when one is up.
///
/// Cloudflare's own speed-test endpoints. Each direction is cut off at
/// [limit], so a slow line costs seconds rather than the whole transfer:
/// at most [downloadBytes] down and [uploadBytes] up.
class SpeedTest {
  SpeedTest({
    Uri? download,
    Uri? upload,
    this.limit = const Duration(seconds: 8),
    this.uploadBytes = 8 * 1024 * 1024,
    this.proxy,
  }) : download =
           download ??
           Uri.parse(
             'https://speed.cloudflare.com/__down?bytes=$downloadBytes',
           ),
       upload = upload ?? Uri.parse('https://speed.cloudflare.com/__up');

  static const int downloadBytes = 20 * 1024 * 1024;

  final Uri download;
  final Uri upload;
  final Duration limit;
  final int uploadBytes;

  /// An [HttpClient.findProxy] answer, where this app's own requests do not
  /// take the tunnel's path on their own (see httpProxyDirective).
  final String? proxy;

  Future<SpeedReport> run() async =>
      (downloadMbps: await _download(), uploadMbps: await _upload());

  Future<double?> _download() async {
    final HttpClient client = _client();
    try {
      final HttpClientResponse response = await (await client.getUrl(
        download,
      )).close().timeout(limit);
      if (response.statusCode != 200) {
        return null;
      }
      // From the first byte of the answer: the connection's setup is the
      // protocol test's business, not the line's speed.
      final Stopwatch clock = Stopwatch()..start();
      final Completer<void> ended = Completer<void>();
      int bytes = 0;
      final StreamSubscription<List<int>> body = response.listen(
        (List<int> chunk) => bytes += chunk.length,
        onDone: ended.complete,
        onError: (Object _) => ended.complete(),
        cancelOnError: true,
      );
      await ended.future.timeout(limit, onTimeout: () {});
      clock.stop();
      unawaited(body.cancel());
      return _mbps(bytes, clock.elapsed);
    } on Object {
      return null;
    } finally {
      client.close(force: true);
    }
  }

  Future<double?> _upload() async {
    final HttpClient client = _client();
    try {
      final HttpClientRequest request = await client
          .postUrl(upload)
          .timeout(limit);
      request.headers.contentType = ContentType.binary;
      request.bufferOutput = false;
      final Uint8List chunk = Uint8List(64 * 1024);
      final Stopwatch clock = Stopwatch()..start();
      int sent = 0;
      while (sent < uploadBytes && clock.elapsed < limit) {
        request.add(chunk);
        await request.flush().timeout(limit);
        sent += chunk.length;
      }
      // Until the server answers, not until the last write: what is still
      // in a buffer on this side has not been uploaded yet.
      // Longer than the sending: on a slow uplink what was written in the
      // last seconds is still on its way, and giving up on the answer turned
      // a slow upload into "could not measure" (a phone at 5 Mbit/s up).
      final HttpClientResponse response = await request.close().timeout(
        limit * 3,
      );
      await response.drain<void>().timeout(limit);
      clock.stop();
      return response.statusCode < 400 ? _mbps(sent, clock.elapsed) : null;
    } on Object {
      return null;
    } finally {
      client.close(force: true);
    }
  }

  HttpClient _client() {
    final HttpClient client = HttpClient()..connectionTimeout = limit;
    final String? through = proxy;
    if (through != null) {
      client.findProxy = (Uri _) => through;
    }
    return client;
  }

  static double? _mbps(int bytes, Duration elapsed) =>
      bytes == 0 || elapsed.inMicroseconds == 0
      ? null
      : bytes * 8 / elapsed.inMicroseconds;
}

/// One decimal below ten, none above: 0.4, 7.3, 86.
String formatMbps(double mbps) => mbps.toStringAsFixed(mbps < 10 ? 1 : 0);
