import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/xray/ech_source.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';

const String _route = 'cloudflare-ech.com+udp://1.1.1.1';

Future<bool> Function(String, String) _answering(Set<String> working) =>
    (String server, String name) async => working.contains(server);

void main() {
  setUp(resetEchServer);

  test('nothing checked yet leaves the route as the server sent it', () {
    expect(withWorkingEchServer(_route), _route);
  });

  test('1.1.1.1 answering keeps it', () async {
    await refreshEchServer(_route, ask: _answering(echLookupServers.toSet()));
    expect(withWorkingEchServer(_route), _route);
  });

  test('1.1.1.1 blocked moves the lookup to the next that answers', () async {
    await refreshEchServer(
      _route,
      ask: _answering(<String>{'udp://9.9.9.9', 'udp://8.8.8.8'}),
    );
    expect(withWorkingEchServer(_route), 'cloudflare-ech.com+udp://8.8.8.8');
  });

  test('no UDP resolver answering falls back to DNS over HTTPS', () async {
    await refreshEchServer(_route, ask: _answering(<String>{}));
    expect(
      withWorkingEchServer(_route),
      'cloudflare-ech.com+https://8.8.8.8/dns-query',
    );
  });

  test('a slow resolver costs at most the timeout', () async {
    final Stopwatch watch = Stopwatch()..start();
    await refreshEchServer(
      _route,
      timeout: const Duration(milliseconds: 100),
      ask: (String server, String name) => server == 'udp://8.8.8.8'
          ? Future<bool>.value(true)
          : Completer<bool>().future,
    );
    expect(watch.elapsed, lessThan(const Duration(seconds: 1)));
    expect(withWorkingEchServer(_route), 'cloudflare-ech.com+udp://8.8.8.8');
  });

  test('the check is reused rather than repeated on every connect', () async {
    int asked = 0;
    Future<bool> count(String server, String name) async {
      asked++;
      return true;
    }

    await refreshEchServer(_route, ask: count);
    await refreshEchServer(_route, ask: count);
    expect(asked, echLookupServers.length);
  });

  test('a key list or a link\'s own resolver is left alone', () async {
    await refreshEchServer(_route, ask: _answering(<String>{'udp://8.8.8.8'}));
    expect(withWorkingEchServer('AEX+/gBB'), 'AEX+/gBB');
    expect(
      withWorkingEchServer('example.com+https://dns.example/dns-query'),
      'example.com+https://dns.example/dns-query',
    );
  });

  test('a key list needs no lookup at all', () async {
    bool asked = false;
    await refreshEchServer(
      'AEX+/gBB',
      ask: (String server, String name) async => asked = true,
    );
    await refreshEchServer(
      null,
      ask: (String s, String n) async => asked = true,
    );
    expect(asked, isFalse);
  });

  test('the question is exactly the wire format, for any record type', () {
    final List<int> name = <int>[1, 97, 2, 98, 99, 0]; // a.bc
    expect(dnsQuery(0x1234, 'a.bc'), <int>[
      0x12,
      0x34,
      1,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      ...name,
      0,
      1,
      0,
      1,
    ]);
    expect(dnsQuery(0x1234, 'a.bc', type: 65).sublist(12), <int>[
      ...name,
      0,
      65,
      0,
      1,
    ]);
  });

  group('dnsAnswerHasType', () {
    Uint8List answer({int rcode = 0, int type = 65, int id = 0x1234}) =>
        Uint8List.fromList(<int>[
          id >> 8, id & 0xff, 0x81, 0x80 | rcode, 0, 1, 0, 1, 0, 0, 0, 0,
          // question: cloudflare-ech.com HTTPS IN
          10, ...'cloudflare'.codeUnits, 3, ...'ech'.codeUnits,
          3, ...'com'.codeUnits, 0, 0, 65, 0, 1,
          // answer: pointer to the name, type, class, TTL, 3 bytes of data
          0xc0, 12, 0, type, 0, 1, 0, 0, 1, 44, 0, 3, 0, 1, 0,
        ]);

    test('an HTTPS record counts', () {
      expect(dnsAnswerHasType(answer(), 0x1234, 65), isTrue);
    });
    test('another record type does not', () {
      expect(dnsAnswerHasType(answer(type: 1), 0x1234, 65), isFalse);
    });
    test('an error or another question\'s answer does not', () {
      expect(dnsAnswerHasType(answer(rcode: 2), 0x1234, 65), isFalse);
      expect(dnsAnswerHasType(answer(), 0x9999, 65), isFalse);
    });
    test('a truncated answer does not', () {
      final Uint8List cut = answer().sublist(0, 40);
      expect(dnsAnswerHasType(cut, 0x1234, 65), isFalse);
    });
  });
}
