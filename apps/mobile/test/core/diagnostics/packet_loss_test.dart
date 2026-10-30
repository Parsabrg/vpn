import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/diagnostics/packet_loss.dart';

/// A stand-in for the resolver: echoes each query back, except every fourth.
Future<RawDatagramSocket> _resolver({int dropEvery = 4}) async {
  final RawDatagramSocket socket = await RawDatagramSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
  );
  int seen = 0;
  socket.listen((RawSocketEvent event) {
    if (event != RawSocketEvent.read) {
      return;
    }
    final Datagram? query = socket.receive();
    if (query == null) {
      return;
    }
    seen++;
    if (seen % dropEvery != 0) {
      socket.send(query.data, query.address, query.port);
    }
  });
  return socket;
}

void main() {
  test('counts the packets that never came back', () async {
    final RawDatagramSocket resolver = await _resolver();
    addTearDown(resolver.close);

    final LossReport report = await PacketLossTest(
      target: InternetAddress.loopbackIPv4,
      port: resolver.port,
      count: 8,
      spacing: const Duration(milliseconds: 5),
      wait: const Duration(milliseconds: 300),
    ).run();

    expect(report.sent, 8);
    expect(report.received, 6);
    expect(lossPercent(report), 25);
    expect(report.median, isNotNull);
    expect(report.jitter, isNotNull);
  });

  test('nothing answering is total loss, not a measurement of zero', () async {
    final RawDatagramSocket silent = await RawDatagramSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    addTearDown(silent.close);

    final LossReport report = await PacketLossTest(
      target: InternetAddress.loopbackIPv4,
      port: silent.port,
      count: 3,
      spacing: const Duration(milliseconds: 5),
      wait: const Duration(milliseconds: 100),
    ).run();

    expect(report.received, 0);
    expect(lossPercent(report), 100);
    expect(report.median, isNull);
  });
}
