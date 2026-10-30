import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/core/servers/server_repository.dart';
import 'package:nebula_mobile/core/storage/xray_credential_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('a saved credential keeps the CA it is verified against', () async {
    // An offline connect uses the saved copy. Without the installation's CA
    // in it, the tunnel it raises fails TLS against an install reached by IP.
    FlutterSecureStorage.setMockInitialValues(<String, String>{});
    final FlutterSecureXrayCredentialStore store =
        FlutterSecureXrayCredentialStore();
    const String ca =
        '-----BEGIN CERTIFICATE-----\nTmVidWxh\n-----END CERTIFICATE-----';

    await store.write(
      serverCode: 'node-1',
      profileCode: 'vless-xhttp-tls',
      credential: const XrayClientResult(
        clientId: 'client-1',
        uuid: 'a1b2c3d4-0000-0000-0000-000000000000',
        serverAddress: '203.0.113.7',
        port: 443,
        sni: '203.0.113.7',
        transport: 'xhttp',
        transportSecurity: 'tls',
        adBlock: false,
        path: '/xhttp-path',
        caCertificate: ca,
      ),
    );
    final XrayClientResult? read = await store.read(
      serverCode: 'node-1',
      profileCode: 'vless-xhttp-tls',
    );

    expect(read?.caCertificate, ca);
    expect(read?.path, '/xhttp-path');
  });
}
