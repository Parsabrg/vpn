import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/diagnostics/diagnostics_report.dart';
import 'package:nebula_mobile/core/diagnostics/speed_test.dart';

void main() {
  late HttpServer server;
  int received = 0;

  setUp(() async {
    received = 0;
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((HttpRequest request) async {
      switch (request.uri.path) {
        case '/down':
          request.response.add(Uint8List(512 * 1024));
          await request.response.close();
        case '/endless':
          // A line too slow to finish: the limit has to end it.
          request.response.bufferOutput = false;
          final Timer feed = Timer.periodic(
            const Duration(milliseconds: 20),
            (_) => request.response.add(Uint8List(1024)),
          );
          unawaited(
            request.response.done.whenComplete(feed.cancel).catchError((_) {}),
          );
        case '/up':
          await for (final List<int> chunk in request) {
            received += chunk.length;
          }
          await request.response.close();
        default:
          request.response.statusCode = HttpStatus.notFound;
          await request.response.close();
      }
    });
  });

  tearDown(() => server.close(force: true));

  Uri at(String path) => Uri.parse('http://127.0.0.1:${server.port}$path');

  test('measures both ways, and uploads what it says it does', () async {
    final SpeedReport report = await SpeedTest(
      download: at('/down'),
      upload: at('/up'),
      uploadBytes: 256 * 1024,
    ).run();
    expect(report.downloadMbps, greaterThan(0));
    expect(report.uploadMbps, greaterThan(0));
    expect(received, 256 * 1024);
  });

  test('a slow line is cut off at the limit and still measured', () async {
    final Stopwatch clock = Stopwatch()..start();
    final SpeedReport report = await SpeedTest(
      download: at('/endless'),
      upload: at('/missing'),
      limit: const Duration(milliseconds: 400),
      uploadBytes: 64 * 1024,
    ).run();
    // About 1 KB every 20 ms is 0.4 Mbps; the exact figure is the timer's.
    expect(report.downloadMbps, inInclusiveRange(0.05, 2));
    expect(clock.elapsed, lessThan(const Duration(seconds: 5)));
    // The server refused the upload: no figure rather than a made-up one.
    expect(report.uploadMbps, isNull);
  });

  test('nothing listening measures nothing', () async {
    final int port = server.port;
    await server.close(force: true);
    final SpeedReport report = await SpeedTest(
      download: Uri.parse('http://127.0.0.1:$port/down'),
      upload: Uri.parse('http://127.0.0.1:$port/up'),
      limit: const Duration(seconds: 2),
    ).run();
    expect(report, (downloadMbps: null, uploadMbps: null));
  });

  test('figures are written the way they are read', () {
    expect(formatMbps(0.42), '0.4');
    expect(formatMbps(7.26), '7.3');
    expect(formatMbps(86.4), '86');
    final String report = diagnosticsReport(
      appVersion: '0.1.20',
      platform: 'windows 10',
      connected: true,
      localProxy: false,
      speed: (downloadMbps: 86.4, uploadMbps: null),
    );
    expect(report, contains('Speed: 86 Mbps down · not measured up'));
  });
}
