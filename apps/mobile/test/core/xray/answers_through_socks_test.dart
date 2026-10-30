import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/xray/local_proxy.dart';

// A self-signed certificate for www.gstatic.com and its key, made for this
// test alone (allowlisted in .gitleaks.toml by exact line): the fake server
// behind the fake proxy presents them.
const String _certificate = '''
-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUa5huVr47kbRKeBhmsde3jSaQPJwwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPd3d3LmdzdGF0aWMuY29tMCAXDTI2MTAxNDA3MDgzNloYDzIx
MjYwOTIwMDcwODM2WjAaMRgwFgYDVQQDDA93d3cuZ3N0YXRpYy5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARix1dR5k4xrOke4jz45L8oGZ8bk2vI+iANlSLB
nGP8mHwUkrZgj2XIl0F1ZoTYeL/3I/Yrha7oQJZQQOnNjqgUo28wbTAdBgNVHQ4E
FgQUpoGqD1IIzt40Wp+O4sdWF5UoegswHwYDVR0jBBgwFoAUpoGqD1IIzt40Wp+O
4sdWF5UoegswDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgg93d3cuZ3N0YXRp
Yy5jb20wCgYIKoZIzj0EAwIDSAAwRQIgddxAU6x8dvmIrHM7EpVGOpleidwTwBEb
Fp5z2n95v/0CIQDtWcbhaUlb3KCcvraDxokdbQr24OmUaYhA/ot8Vax0DQ==
-----END CERTIFICATE-----
''';
const String _key = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRAVYax/KpZdLz2Mp
96oCrwQiw6X6fm3fZel9yx7ZgoihRANCAARix1dR5k4xrOke4jz45L8oGZ8bk2vI
+iANlSLBnGP8mHwUkrZgj2XIl0F1ZoTYeL/3I/Yrha7oQJZQQOnNjqgU
-----END PRIVATE KEY-----
''';

/// A SOCKS5 proxy that checks the credentials and connects every CONNECT to
/// a TLS server answering each request with [status] -- or, with [stall],
/// completing the handshake and then answering nothing, as the throttled
/// direct address did.
Future<ServerSocket> _proxy({int status = 204, bool stall = false}) async {
  final SecurityContext context = SecurityContext()
    ..useCertificateChainBytes(utf8.encode(_certificate))
    ..usePrivateKeyBytes(utf8.encode(_key));
  final SecureServerSocket site = await SecureServerSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
    context,
  );
  site.listen((SecureSocket client) {
    client.listen((List<int> _) {
      if (!stall) {
        client.add(ascii.encode('HTTP/1.1 $status No Content\r\n\r\n'));
        client.close();
      }
    });
  });
  addTearDown(site.close);
  final ServerSocket server = await ServerSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
  );
  server.listen((Socket client) {
    int step = 0;
    Socket? upstream;
    client.listen((List<int> data) async {
      switch (step++) {
        case 0:
          client.add(<int>[5, 2]);
        case 1:
          final int ulen = data[1];
          final String user = utf8.decode(data.sublist(2, 2 + ulen));
          client.add(<int>[1, user == 'u' ? 0 : 1]);
        case 2:
          final Socket up = upstream = await Socket.connect(
            InternetAddress.loopbackIPv4,
            site.port,
          );
          up.listen(client.add, onDone: client.destroy);
          client.add(<int>[5, 0, 0, 1, 127, 0, 0, 1, 1, 187]);
        default:
          upstream?.add(data);
      }
    });
  });
  return server;
}

/// A SOCKS5 proxy with a UDP relay that answers a DNS question itself: with
/// [rcode], and one answer unless [answers] is 0. Silent when [silent].
Future<ServerSocket> _udpProxy({
  int rcode = 0,
  int answers = 1,
  bool silent = false,
}) async {
  final RawDatagramSocket relay = await RawDatagramSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
  );
  relay.listen((RawSocketEvent event) {
    final Datagram? d = relay.receive();
    if (d == null || silent) {
      return;
    }
    // SOCKS header (10 bytes for IPv4), then the query.
    final Uint8List query = d.data.sublist(10);
    final List<int> answer = <int>[
      ...d.data.sublist(0, 10),
      query[0],
      query[1],
      0x81,
      0x80 | rcode,
      0,
      1,
      0,
      answers,
      0,
      0,
      0,
      0,
      ...query.sublist(12),
      // The answer itself: the question's name by pointer, A, IN, a TTL,
      // and 203.0.113.7.
      if (answers > 0) ...<int>[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4],
      if (answers > 0) ...<int>[203, 0, 113, 7],
    ];
    relay.send(answer, d.address, d.port);
  });
  final ServerSocket server = await ServerSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
  );
  server.listen((Socket client) {
    int step = 0;
    client.listen((List<int> data) {
      switch (step++) {
        case 0:
          client.add(<int>[5, 2]);
        case 1:
          final String user = utf8.decode(data.sublist(2, 2 + data[1]));
          client.add(<int>[1, user == 'u' ? 0 : 1]);
        case 2:
          client.add(<int>[
            5,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            relay.port >> 8,
            relay.port & 0xff,
          ]);
      }
    });
  });
  addTearDown(relay.close);
  return server;
}

void main() {
  group('a DNS question through the proxy', () {
    final InternetAddress resolver = InternetAddress('94.140.14.140');
    Future<bool> ask(ServerSocket server, {String user = 'u'}) =>
        resolvesThroughSocks(
          LocalProxy(port: server.port, username: user, password: 'p'),
          resolver,
          timeout: const Duration(milliseconds: 500),
        );

    test('answered counts', () async {
      final ServerSocket server = await _udpProxy();
      addTearDown(server.close);
      expect(await ask(server), isTrue);
    });

    test('the addresses are read out of the answer', () async {
      final ServerSocket server = await _udpProxy();
      addTearDown(server.close);
      final List<InternetAddress> addresses = await lookupThroughSocks(
        LocalProxy(port: server.port, username: 'u', password: 'p'),
        resolver,
        'www.example.com',
        timeout: const Duration(milliseconds: 500),
      );
      expect(addresses.map((InternetAddress a) => a.address), <String>[
        '203.0.113.7',
      ]);
    });

    test('unanswered, refused, empty or refused login do not', () async {
      for (final ServerSocket server in <ServerSocket>[
        await _udpProxy(silent: true),
        await _udpProxy(rcode: 5),
        await _udpProxy(answers: 0),
      ]) {
        addTearDown(server.close);
        expect(await ask(server), isFalse);
      }
      final ServerSocket server = await _udpProxy();
      addTearDown(server.close);
      expect(await ask(server, user: 'x'), isFalse);
    });
  });

  group('an HTTPS request through the proxy', () {
    Future<bool> ask(
      ServerSocket server, {
      String user = 'u',
      bool trustTestCertificate = true,
    }) => answersThroughSocks(
      LocalProxy(port: server.port, username: user, password: 'p'),
      timeout: const Duration(seconds: 2),
      onBadCertificate: trustTestCertificate ? (_) => true : null,
    );

    test('answered counts', () async {
      final ServerSocket server = await _proxy();
      addTearDown(server.close);
      expect(await ask(server), isTrue);
    });

    test('a handshake and then nothing does not', () async {
      // The throttled direct address: TLS inside the tunnel got through its
      // handshake and no further.
      final ServerSocket server = await _proxy(stall: true);
      addTearDown(server.close);
      expect(await ask(server), isFalse);
    });

    test(
      'an error status, refused credentials or a bad certificate do not',
      () async {
        final ServerSocket refusing = await _proxy(status: 503);
        addTearDown(refusing.close);
        expect(await ask(refusing), isFalse);
        final ServerSocket server = await _proxy();
        addTearDown(server.close);
        expect(await ask(server, user: 'x'), isFalse);
        // Not a certificate anyone trusts: a blockpage is not an answer.
        expect(await ask(server, trustTestCertificate: false), isFalse);
      },
    );
  });
}
