import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../servers/server_repository.dart';

/// The last credential the server issued for a server/profile pair, kept so
/// a tunnel can still be raised when the server cannot be reached.
///
/// Every connect asks the API for a fresh credential. That is the right thing
/// when the API is reachable -- but it means a blocked address takes the
/// tunnel down with it, even though the credential already on the phone would
/// still work: an Xray client is a UUID on an inbound, valid until an admin
/// revokes it, not a short-lived token.
///
/// Held in secure storage, not preferences: it is a credential that grants
/// access to the tunnel, and the proxy's own password is kept the same way.
abstract interface class XrayCredentialStore {
  Future<XrayClientResult?> read({
    required String serverCode,
    required String profileCode,
  });

  Future<void> write({
    required String serverCode,
    required String profileCode,
    required XrayClientResult credential,
  });

  /// Forgets one credential. Called whenever the server is told to revoke it:
  /// a saved copy of a revoked credential raises a tunnel that carries
  /// nothing while the app says it is connected.
  Future<void> forget({
    required String serverCode,
    required String profileCode,
  });

  /// Dropped on sign-out, with everything else that identified the account.
  Future<void> clear();
}

Map<String, dynamic> _encode(XrayClientResult c) => <String, dynamic>{
  'client_id': c.clientId,
  'uuid': c.uuid,
  'server_address': c.serverAddress,
  'port': c.port,
  'sni': c.sni,
  'transport': c.transport,
  'transport_security': c.transportSecurity,
  'ad_block': c.adBlock,
  'path': c.path,
  'service_name': c.serviceName,
  'obfs_password': c.obfsPassword,
  'client_dns': c.clientDns,
  'ca_certificate': c.caCertificate,
  'ech_config_list': c.echConfigList,
  'protocol': c.protocol,
  'password': c.password,
  'method': c.method,
  'encryption': c.encryption,
  'flow': c.flow,
  'reality_public_key': c.realityPublicKey,
  'reality_short_id': c.realityShortId,
  'fingerprint': c.fingerprint,
};

XrayClientResult _decode(Map<String, dynamic> json) => XrayClientResult(
  clientId: json['client_id'] as String,
  uuid: json['uuid'] as String,
  serverAddress: json['server_address'] as String,
  port: json['port'] as int,
  sni: json['sni'] as String,
  transport: json['transport'] as String,
  transportSecurity: json['transport_security'] as String,
  adBlock: json['ad_block'] as bool? ?? false,
  path: json['path'] as String?,
  serviceName: json['service_name'] as String?,
  obfsPassword: json['obfs_password'] as String?,
  clientDns: clientDnsFrom(json['client_dns']),
  caCertificate: json['ca_certificate'] as String?,
  echConfigList: json['ech_config_list'] as String?,
  protocol: json['protocol'] as String? ?? 'vless',
  password: json['password'] as String?,
  method: json['method'] as String?,
  encryption: json['encryption'] as String?,
  flow: json['flow'] as String?,
  realityPublicKey: json['reality_public_key'] as String?,
  realityShortId: json['reality_short_id'] as String?,
  fingerprint: json['fingerprint'] as String?,
);

class FlutterSecureXrayCredentialStore implements XrayCredentialStore {
  FlutterSecureXrayCredentialStore({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  static const String _prefix = 'nebula.xray_credential.';

  final FlutterSecureStorage _storage;

  String _key(String serverCode, String profileCode) =>
      '$_prefix$serverCode.$profileCode';

  @override
  Future<XrayClientResult?> read({
    required String serverCode,
    required String profileCode,
  }) async {
    final String? stored = await _storage.read(
      key: _key(serverCode, profileCode),
    );
    if (stored == null) {
      return null;
    }
    try {
      return _decode(jsonDecode(stored) as Map<String, dynamic>);
    } on FormatException {
      // Written by an older build whose shape has since changed. A tunnel
      // is better refused than raised from something half-understood.
      return null;
    }
  }

  @override
  Future<void> write({
    required String serverCode,
    required String profileCode,
    required XrayClientResult credential,
  }) {
    return _storage.write(
      key: _key(serverCode, profileCode),
      value: jsonEncode(_encode(credential)),
    );
  }

  @override
  Future<void> forget({
    required String serverCode,
    required String profileCode,
  }) => _storage.delete(key: _key(serverCode, profileCode));

  @override
  Future<void> clear() async {
    final Map<String, String> all = await _storage.readAll();
    for (final String key in all.keys) {
      if (key.startsWith(_prefix)) {
        await _storage.delete(key: key);
      }
    }
  }
}

class InMemoryXrayCredentialStore implements XrayCredentialStore {
  final Map<String, XrayClientResult> entries = <String, XrayClientResult>{};

  @override
  Future<XrayClientResult?> read({
    required String serverCode,
    required String profileCode,
  }) async => entries['$serverCode.$profileCode'];

  @override
  Future<void> write({
    required String serverCode,
    required String profileCode,
    required XrayClientResult credential,
  }) async {
    entries['$serverCode.$profileCode'] = credential;
  }

  @override
  Future<void> forget({
    required String serverCode,
    required String profileCode,
  }) async {
    entries.remove('$serverCode.$profileCode');
  }

  @override
  Future<void> clear() async => entries.clear();
}
