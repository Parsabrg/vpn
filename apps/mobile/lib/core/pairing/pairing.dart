import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';

/// Pairing: how one generic build of the app learns which deployment it
/// belongs to, instead of having an address compiled into it.
///
/// The operator gives a person a pairing link (as a QR code in the admin
/// panel, or as text):
///
///     https://vpn.example.org/pair#v=1&d=<deployment id>&ca=<sha256>
///
/// The link is the trust anchor. `d` names the deployment, and `ca`, present
/// when the installation uses a certificate authority of its own (an install
/// reached by IP address), is the SHA-256 of that CA certificate. See
/// services/api/src/nebula_api/pairing.py for the server's side.
///
/// Pairing then:
///
///   1. fetches `/v1/pairing` from the link's origin. With a `ca` pin, this
///      first request cannot verify the server yet, so the only thing taken
///      from its answer is the CA certificate, and only if its SHA-256 matches
///      the pin;
///   2. fetches the record again over a connection verified against that CA
///      and nothing else, which proves the server holds a certificate the
///      pinned CA issued;
///   3. accepts the record only if its deployment id is the one the link
///      names.
///
/// A link altered on its way to the person, or a server that is not the one
/// the link names, fails one of these and pairs with nothing.
class PairingLink {
  const PairingLink({
    required this.apiUrl,
    required this.deploymentId,
    required this.caSha256,
  });

  /// Origin of the API, no trailing slash.
  final Uri apiUrl;

  /// Absent only for an address typed by hand.
  final String? deploymentId;

  /// Lowercase hex. Absent for an installation with a publicly trusted
  /// certificate.
  final String? caSha256;

  static final RegExp _uuid = RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
  );
  static final RegExp _sha256 = RegExp(r'^[0-9a-f]{64}$');

  /// Reads a pairing link, the app-scheme form of one, or a bare address.
  ///
  /// [allowPlainHttp] exists for development builds talking to a local API;
  /// release builds never pass it, because credentials travel over this.
  static PairingLink parse(String input, {bool allowPlainHttp = false}) {
    final String text = input.trim();
    final Uri uri;
    try {
      uri = Uri.parse(text);
    } on FormatException {
      throw const PairingException(PairingFailure.malformed);
    }

    Map<String, String> values;
    Uri origin;
    if (uri.scheme == 'nebula' && uri.host == 'pair') {
      values = uri.queryParameters;
      final String? api = values['u'];
      if (api == null) {
        throw const PairingException(PairingFailure.malformed);
      }
      origin = _origin(Uri.tryParse(api), allowPlainHttp);
    } else if (uri.scheme == 'https' || uri.scheme == 'http') {
      origin = _origin(uri, allowPlainHttp);
      values = uri.fragment.isEmpty
          ? const <String, String>{}
          : Uri.splitQueryString(uri.fragment);
      if (values.isNotEmpty && uri.path != '/pair') {
        throw const PairingException(PairingFailure.malformed);
      }
    } else {
      throw const PairingException(PairingFailure.malformed);
    }

    final String? version = values['v'];
    if (version != null && version != '1') {
      throw const PairingException(PairingFailure.unsupportedVersion);
    }
    final String? deployment = values['d']?.toLowerCase();
    if (deployment != null && !_uuid.hasMatch(deployment)) {
      throw const PairingException(PairingFailure.malformed);
    }
    final String? pin = values['ca']?.toLowerCase();
    if (pin != null && !_sha256.hasMatch(pin)) {
      throw const PairingException(PairingFailure.malformed);
    }
    return PairingLink(apiUrl: origin, deploymentId: deployment, caSha256: pin);
  }

  static Uri _origin(Uri? uri, bool allowPlainHttp) {
    if (uri == null || uri.host.isEmpty) {
      throw const PairingException(PairingFailure.malformed);
    }
    if (uri.scheme != 'https' && !(allowPlainHttp && uri.scheme == 'http')) {
      throw const PairingException(PairingFailure.notHttps);
    }
    return Uri(scheme: uri.scheme, host: uri.host, port: uri.port);
  }
}

/// What the app keeps once paired. Stored in secure storage.
class Pairing {
  const Pairing({
    required this.apiUrl,
    required this.deploymentId,
    required this.deploymentName,
    required this.caCertificatePem,
    required this.caSha256,
    required this.profiles,
  });

  /// A build that carries its address (`--dart-define=API_BASE_URL`), as
  /// every build did before pairing. It is trusted as the operator who made
  /// the build decided, and has no deployment identity to check.
  factory Pairing.preset(String apiUrl) => Pairing(
    apiUrl: apiUrl,
    deploymentId: null,
    deploymentName: null,
    caCertificatePem: null,
    caSha256: null,
    profiles: const <String>[],
  );

  final String apiUrl;
  final String? deploymentId;
  final String? deploymentName;

  /// The installation's own CA, when it has one. Everything this app sends to
  /// the API is then verified against it.
  final String? caCertificatePem;
  final String? caSha256;
  final List<String> profiles;

  Map<String, Object?> toJson() => <String, Object?>{
    'api_url': apiUrl,
    'deployment_id': deploymentId,
    'deployment_name': deploymentName,
    'ca_certificate': caCertificatePem,
    'ca_sha256': caSha256,
    'profiles': profiles,
  };

  static Pairing fromJson(Map<String, Object?> json) => Pairing(
    apiUrl: json['api_url']! as String,
    deploymentId: json['deployment_id'] as String?,
    deploymentName: json['deployment_name'] as String?,
    caCertificatePem: json['ca_certificate'] as String?,
    caSha256: json['ca_sha256'] as String?,
    profiles: <String>[
      for (final Object? profile
          in (json['profiles'] as List<Object?>?) ?? const <Object?>[])
        if (profile is String) profile,
    ],
  );
}

enum PairingFailure {
  malformed,
  notHttps,
  unsupportedVersion,
  unreachable,
  certificateMismatch,
  deploymentMismatch,
  needsLink,
}

class PairingException implements Exception {
  const PairingException(this.failure, [this.detail]);

  final PairingFailure failure;
  final String? detail;

  @override
  String toString() =>
      'PairingException(${failure.name}${detail == null ? '' : ': $detail'})';
}

/// Fetches `/v1/pairing` from [origin]. [trustOnly] is a PEM CA: when given,
/// the connection is verified against it and nothing else. [unverified] is
/// for the one request that only fetches a CA to be checked against a pin.
typedef PairingFetch =
    Future<Map<String, Object?>> Function(
      Uri origin, {
      String? trustOnly,
      bool unverified,
    });

class PairingClient {
  PairingClient({PairingFetch? fetch}) : _fetch = fetch ?? fetchPairingRecord;

  final PairingFetch _fetch;

  Future<Pairing> pair(PairingLink link) async {
    final String? pin = link.caSha256;
    Map<String, Object?> record;
    String? caPem;
    if (pin == null) {
      try {
        record = await _fetch(link.apiUrl);
      } on HandshakeException {
        // The server's certificate is not one this device trusts, and the
        // address carried no pin to trust it by: it needs the full link.
        throw const PairingException(PairingFailure.needsLink);
      }
    } else {
      final Map<String, Object?> first = await _fetch(
        link.apiUrl,
        unverified: true,
      );
      final Object? offered = first['ca_certificate'];
      if (offered is! String || await caFingerprint(offered) != pin) {
        throw const PairingException(PairingFailure.certificateMismatch);
      }
      caPem = offered;
      try {
        record = await _fetch(link.apiUrl, trustOnly: caPem);
      } on HandshakeException {
        throw const PairingException(PairingFailure.certificateMismatch);
      }
    }

    if (record['version'] != 1) {
      throw const PairingException(PairingFailure.unsupportedVersion);
    }
    final Object? deployment = record['deployment_id'];
    if (deployment is! String ||
        (link.deploymentId != null &&
            deployment.toLowerCase() != link.deploymentId)) {
      throw const PairingException(PairingFailure.deploymentMismatch);
    }
    final Object? name = record['deployment_name'];
    return Pairing(
      // Where the link pointed, not what the record says: the record is
      // this server describing itself, the link is what the person was given.
      apiUrl: link.apiUrl.toString(),
      deploymentId: deployment.toLowerCase(),
      deploymentName: name is String ? name : null,
      caCertificatePem: caPem,
      caSha256: pin,
      profiles: <String>[
        for (final Object? profile
            in (record['profiles'] as List<Object?>?) ?? const <Object?>[])
          if (profile is String) profile,
      ],
    );
  }
}

/// SHA-256 over the DER encoding of a PEM certificate, lowercase hex: what
/// the server puts in the link.
Future<String> caFingerprint(String pem) async {
  final String body = pem
      .replaceAll('-----BEGIN CERTIFICATE-----', '')
      .replaceAll('-----END CERTIFICATE-----', '')
      .replaceAll(RegExp(r'\s'), '');
  final List<int> der;
  try {
    der = base64.decode(body);
  } on FormatException {
    return '';
  }
  final Hash hash = await Sha256().hash(der);
  return hash.bytes.map((int b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// A security context that trusts [caPem] in addition to, or instead of,
/// the platform's roots.
SecurityContext pinnedContext(String caPem, {required bool alsoSystem}) {
  final SecurityContext context = SecurityContext(withTrustedRoots: alsoSystem);
  context.setTrustedCertificatesBytes(utf8.encode(caPem));
  return context;
}

/// [deadline] bounds the whole request. `connectionTimeout` covers only the
/// TCP connect; the TLS handshake happens inside `getUrl`, and a network that
/// accepts the connection but swallows the handshake -- a censor dropping
/// TLS, or another VPN's tunnel that cannot reach the address -- left the
/// pairing screen on "Checking the server" for good. Seen on a phone.
Future<Map<String, Object?>> fetchPairingRecord(
  Uri origin, {
  String? trustOnly,
  bool unverified = false,
  Duration deadline = const Duration(seconds: 20),
}) async {
  final HttpClient client = HttpClient(
    context: trustOnly == null
        ? null
        : pinnedContext(trustOnly, alsoSystem: false),
  )..connectionTimeout = const Duration(seconds: 10);
  if (unverified) {
    // Only the CA certificate is read from this answer, and it is checked
    // against the pin before anything relies on it.
    client.badCertificateCallback = (X509Certificate _, String _, int _) =>
        true;
  }
  try {
    final (int status, String text) = await () async {
      final HttpClientRequest request = await client.getUrl(
        origin.replace(path: '/v1/pairing'),
      );
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      final HttpClientResponse response = await request.close();
      return (
        response.statusCode,
        await response.transform(utf8.decoder).join(),
      );
    }().timeout(deadline);
    if (status != 200) {
      throw PairingException(PairingFailure.unreachable, 'HTTP $status');
    }
    final Object? decoded = jsonDecode(text);
    if (decoded is! Map<String, Object?>) {
      throw const PairingException(PairingFailure.unreachable, 'not a record');
    }
    return decoded;
  } on HandshakeException {
    rethrow;
  } on PairingException {
    rethrow;
  } on Object catch (error) {
    throw PairingException(PairingFailure.unreachable, error.toString());
  } finally {
    client.close(force: true);
  }
}
