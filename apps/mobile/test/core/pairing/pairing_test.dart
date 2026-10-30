import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/pairing/pairing.dart';

const String _deployment = '7d3c1f2e-0b5a-4c9d-8e61-2f4a9b0c1d2e';
final String _pin = 'ab' * 32;

void main() {
  group('reading a link', () {
    test('the link the admin panel shows', () {
      final PairingLink link = PairingLink.parse(
        'https://203.0.113.7:8443/pair#v=1&d=$_deployment&ca=$_pin',
      );

      expect(link.apiUrl.toString(), 'https://203.0.113.7:8443');
      expect(link.deploymentId, _deployment);
      expect(link.caSha256, _pin);
    });

    test('the app-scheme form carries the same values', () {
      final PairingLink link = PairingLink.parse(
        'nebula://pair?u=${Uri.encodeComponent('https://vpn.example.org')}'
        '&d=$_deployment',
      );

      expect(link.apiUrl.toString(), 'https://vpn.example.org');
      expect(link.deploymentId, _deployment);
      expect(link.caSha256, isNull);
    });

    test('a bare address, typed by hand', () {
      final PairingLink link = PairingLink.parse('  https://vpn.example.org/ ');

      expect(link.apiUrl.toString(), 'https://vpn.example.org');
      expect(link.deploymentId, isNull);
    });

    test('plain http is refused unless a development build allows it', () {
      expect(
        () => PairingLink.parse('http://vpn.example.org'),
        throwsA(_failure(PairingFailure.notHttps)),
      );
      expect(
        PairingLink.parse(
          'http://10.0.2.2:8000',
          allowPlainHttp: true,
        ).apiUrl.toString(),
        'http://10.0.2.2:8000',
      );
    });

    test('a damaged or foreign link is refused, not half-read', () {
      for (final String bad in <String>[
        'vpn.example.org',
        'https://vpn.example.org/pair#v=1&d=not-a-uuid',
        'https://vpn.example.org/pair#v=1&d=$_deployment&ca=short',
        'https://vpn.example.org/elsewhere#v=1&d=$_deployment',
        'ftp://vpn.example.org',
        'nebula://pair?d=$_deployment',
      ]) {
        expect(
          () => PairingLink.parse(bad),
          throwsA(_failure(PairingFailure.malformed)),
          reason: bad,
        );
      }
      expect(
        () => PairingLink.parse('https://vpn.example.org/pair#v=2&d=x'),
        throwsA(_failure(PairingFailure.unsupportedVersion)),
      );
    });
  });

  group('pairing, with the server faked', () {
    Map<String, Object?> record({String deployment = _deployment}) =>
        <String, Object?>{
          'version': 1,
          'deployment_id': deployment,
          'deployment_name': 'Home',
          'api_url': 'https://vpn.example.org',
          'ca_certificate': null,
          'ca_sha256': null,
          'profiles': <Object?>['wireguard-native'],
        };

    test('a publicly trusted install pairs on its own trust', () async {
      final PairingClient client = PairingClient(
        fetch: (Uri origin, {String? trustOnly, bool unverified = false}) {
          expect(unverified, isFalse);
          expect(trustOnly, isNull);
          return Future<Map<String, Object?>>.value(record());
        },
      );

      final Pairing pairing = await client.pair(
        PairingLink.parse('https://vpn.example.org/pair#v=1&d=$_deployment'),
      );

      expect(pairing.deploymentName, 'Home');
      expect(pairing.caCertificatePem, isNull);
      expect(pairing.profiles, <String>['wireguard-native']);
    });

    test('a server that is not the one the link names is refused', () async {
      final PairingClient client = PairingClient(
        fetch: (Uri origin, {String? trustOnly, bool unverified = false}) =>
            Future<Map<String, Object?>>.value(
              record(deployment: '00000000-0000-4000-8000-000000000000'),
            ),
      );

      await expectLater(
        client.pair(
          PairingLink.parse('https://vpn.example.org/pair#v=1&d=$_deployment'),
        ),
        throwsA(_failure(PairingFailure.deploymentMismatch)),
      );
    });

    test('a certificate this device does not trust needs the full link', () {
      final PairingClient client = PairingClient(
        fetch: (Uri origin, {String? trustOnly, bool unverified = false}) =>
            throw const HandshakeException('unknown issuer'),
      );

      expect(
        client.pair(PairingLink.parse('https://203.0.113.7')),
        throwsA(_failure(PairingFailure.needsLink)),
      );
    });
  });

  test('a server that never answers is given up on, not waited for', () async {
    // Seen on a phone: the connection was accepted -- by another VPN's tunnel
    // that could not reach the address -- and the TLS handshake never
    // finished, so pairing sat on "Checking the server" for good. A censor
    // dropping TLS does the same.
    final ServerSocket silent = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final List<Socket> held = <Socket>[];
    silent.listen(held.add);
    addTearDown(() async {
      for (final Socket socket in held) {
        socket.destroy();
      }
      await silent.close();
    });

    final Stopwatch watch = Stopwatch()..start();
    await expectLater(
      fetchPairingRecord(
        Uri.parse('https://127.0.0.1:${silent.port}'),
        unverified: true,
        deadline: const Duration(seconds: 1),
      ),
      throwsA(_failure(PairingFailure.unreachable)),
    );
    expect(watch.elapsed, lessThan(const Duration(seconds: 5)));
  });

  group('pairing over real TLS', () {
    late _Pki pki;
    HttpServer? server;

    setUpAll(() async {
      pki = await _Pki.create();
    });

    tearDown(() async {
      await server?.close(force: true);
      server = null;
    });

    Future<Uri> serve({
      required String leaf,
      required String key,
      required String offeredCa,
    }) async {
      final SecurityContext context = SecurityContext()
        ..useCertificateChainBytes(utf8.encode(leaf))
        ..usePrivateKeyBytes(utf8.encode(key));
      final HttpServer listening = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        context,
      );
      server = listening;
      listening.listen((HttpRequest request) {
        request.response
          ..headers.contentType = ContentType.json
          ..write(
            jsonEncode(<String, Object?>{
              'version': 1,
              'deployment_id': _deployment,
              'deployment_name': 'Home',
              'api_url': 'https://127.0.0.1:${listening.port}',
              'ca_certificate': offeredCa,
              'ca_sha256': null,
              'profiles': <Object?>['wireguard-native'],
            }),
          )
          ..close();
      });
      return Uri.parse('https://127.0.0.1:${listening.port}');
    }

    test('the pinned CA is checked, then the server is verified against '
        'it', () async {
      final Uri origin = await serve(
        leaf: pki.leaf,
        key: pki.leafKey,
        offeredCa: pki.ca,
      );
      final String pin = await caFingerprint(pki.ca);

      final Pairing pairing = await PairingClient().pair(
        PairingLink.parse('$origin/pair#v=1&d=$_deployment&ca=$pin'),
      );

      expect(pairing.caSha256, pin);
      expect(pairing.caCertificatePem, pki.ca);
    }, skip: _Pki.missing);

    test('a CA that is not the pinned one is refused', () async {
      final Uri origin = await serve(
        leaf: pki.otherLeaf,
        key: pki.otherKey,
        offeredCa: pki.otherCa,
      );
      final String pin = await caFingerprint(pki.ca);

      await expectLater(
        PairingClient().pair(
          PairingLink.parse('$origin/pair#v=1&d=$_deployment&ca=$pin'),
        ),
        throwsA(_failure(PairingFailure.certificateMismatch)),
      );
    }, skip: _Pki.missing);

    test('offering the pinned CA without holding a certificate it issued '
        'is refused', () async {
      // Someone who copied the public CA certificate but not its key: the
      // first answer passes the pin, the verified second request cannot.
      final Uri origin = await serve(
        leaf: pki.otherLeaf,
        key: pki.otherKey,
        offeredCa: pki.ca,
      );
      final String pin = await caFingerprint(pki.ca);

      await expectLater(
        PairingClient().pair(
          PairingLink.parse('$origin/pair#v=1&d=$_deployment&ca=$pin'),
        ),
        throwsA(_failure(PairingFailure.certificateMismatch)),
      );
    }, skip: _Pki.missing);

    test(
      'an installed server, when one is named',
      () async {
        // NEBULA_PAIRING_LINK=<the link `nebulactl pair` prints>
        final String link = Platform.environment['NEBULA_PAIRING_LINK']!;

        final Pairing pairing = await PairingClient().pair(
          PairingLink.parse(link),
        );

        expect(pairing.deploymentId, PairingLink.parse(link).deploymentId);
      },
      skip: Platform.environment['NEBULA_PAIRING_LINK'] == null,
    );
  });
}

Matcher _failure(PairingFailure failure) => isA<PairingException>().having(
  (PairingException error) => error.failure,
  'failure',
  failure,
);

/// Two throwaway CAs, each with a leaf for 127.0.0.1, made with openssl so no
/// private key is committed to the repository.
class _Pki {
  _Pki(this._directory);

  final Directory _directory;

  static final Object missing = _opensslMissing()
      ? 'openssl is not installed'
      : false;

  static bool _opensslMissing() {
    try {
      return Process.runSync('openssl', <String>['version']).exitCode != 0;
    } on ProcessException {
      return true;
    }
  }

  String _read(String name) =>
      File('${_directory.path}/$name').readAsStringSync();

  String get ca => _read('ca.pem');
  String get leaf => _read('leaf.pem');
  String get leafKey => _read('leaf.key');
  String get otherCa => _read('other-ca.pem');
  String get otherLeaf => _read('other-leaf.pem');
  String get otherKey => _read('other-leaf.key');

  static Future<_Pki> create() async {
    final Directory directory = await Directory.systemTemp.createTemp('pki');
    if (missing != false) {
      return _Pki(directory);
    }
    Future<void> run(List<String> arguments) async {
      final ProcessResult result = await Process.run(
        'openssl',
        arguments,
        workingDirectory: directory.path,
      );
      if (result.exitCode != 0) {
        throw StateError('openssl ${arguments.first}: ${result.stderr}');
      }
    }

    File('${directory.path}/leaf.ext').writeAsStringSync(
      'subjectAltName=IP:127.0.0.1\n'
      'extendedKeyUsage=serverAuth\n'
      'basicConstraints=critical,CA:FALSE\n',
    );
    for (final String prefix in <String>['', 'other-']) {
      await run(<String>[
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '2',
        '-subj',
        '/CN=${prefix}test root',
        '-keyout',
        '${prefix}ca.key',
        '-out',
        '${prefix}ca.pem',
      ]); // format: skip
      await run(<String>[
        'req',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-subj',
        '/CN=127.0.0.1',
        '-keyout',
        '${prefix}leaf.key',
        '-out',
        '${prefix}leaf.csr',
      ]); // format: skip
      await run(<String>[
        'x509',
        '-req',
        '-in',
        '${prefix}leaf.csr',
        '-CA',
        '${prefix}ca.pem',
        '-CAkey',
        '${prefix}ca.key',
        '-CAcreateserial',
        '-days',
        '2',
        '-extfile',
        'leaf.ext',
        '-out',
        '${prefix}leaf.pem',
      ]); // format: skip
    }
    return _Pki(directory);
  }
}
