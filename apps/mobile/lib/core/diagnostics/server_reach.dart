import 'dart:async';
import 'dart:io';

import '../servers/server_repository.dart';

/// Why a tunnel that carried nothing did not get through, as far as can be
/// told from outside it: the way Xray reaches the server, step by step, with
/// no tunnel up.
///
/// Read from the server, not from Xray's log. Measured: at the level the app
/// runs the core (warning) Xray logs nothing about a failed outbound, and at
/// info, where it does say why, it also logs every destination visited --
/// a browsing history this app deliberately does not keep.
enum ServerReach {
  /// Name, connection and certificate all fine: the protocol itself did not
  /// get through, which is what a network blocking it looks like.
  reachable,

  /// The server's name does not resolve from this network.
  nameNotFound,

  /// No connection opens to the server's port.
  unreachable,

  /// The connection opens but the certificate is not the server's: a
  /// network intercepting TLS, or a captive portal.
  certificateRejected,
}

typedef ServerReachCheck = Future<ServerReach> Function(XrayClientResult);

/// Name, then TCP, then TLS -- each only where the transport uses it.
/// Hysteria2 is UDP: only its name can be checked. REALITY presents another
/// site's certificate by design, and plain transports none.
Future<ServerReach> checkServerReach(XrayClientResult client) async {
  final String host = client.serverAddress;
  InternetAddress? address = InternetAddress.tryParse(host);
  if (address == null) {
    try {
      final List<InternetAddress> found = await InternetAddress.lookup(
        host,
      ).timeout(const Duration(seconds: 5));
      if (found.isEmpty) {
        return ServerReach.nameNotFound;
      }
      address = found.first;
    } on Object {
      return ServerReach.nameNotFound;
    }
  }
  if (client.transport == 'hysteria') {
    return ServerReach.reachable;
  }
  final Socket socket;
  try {
    socket = await Socket.connect(
      address,
      client.port,
      timeout: const Duration(seconds: 5),
    );
  } on Object {
    return ServerReach.unreachable;
  }
  if (client.transportSecurity != 'tls') {
    socket.destroy();
    return ServerReach.reachable;
  }
  // Against the deployment's own CA alone when it has one, as the tunnel
  // itself is (see renderXrayClientConfigJson).
  final String? ca = client.caCertificate;
  final SecurityContext context = ca == null
      ? SecurityContext.defaultContext
      : (SecurityContext(withTrustedRoots: false)
          ..setTrustedCertificatesBytes(ca.codeUnits));
  try {
    final SecureSocket secure = await SecureSocket.secure(
      socket,
      host: client.sni,
      context: context,
    ).timeout(const Duration(seconds: 6));
    secure.destroy();
    return ServerReach.reachable;
  } on HandshakeException catch (error) {
    // Only a certificate that failed verification. A handshake cut off
    // midway -- "terminated during handshake", what DPI resets look like --
    // is the protocol being blocked, not the certificate.
    return '$error'.contains('CERTIFICATE_VERIFY_FAILED')
        ? ServerReach.certificateRejected
        : ServerReach.reachable;
  } on Object {
    // A handshake that stalls rather than fails is a network dropping it:
    // the protocol is what is blocked, not the server unreachable.
    socket.destroy();
    return ServerReach.reachable;
  }
}
