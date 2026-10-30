import 'dart:async';

import 'package:nebula_mobile/core/servers/server_repository.dart';

class FakeServerRepository implements ServerRepository {
  List<AvailableServer> servers = <AvailableServer>[];
  Object? listError;

  WireGuardPeerResult? requestPeerResult;

  /// Holds [requestPeer] until completed: a request still in flight.
  Completer<void>? requestPeerGate;
  Object? requestPeerError;
  int requestPeerCalls = 0;
  String? lastRequestedServerCode;
  String? lastRequestedProfileCode;
  String? lastRequestedPublicKey;

  int revokePeerCalls = 0;
  String? lastRevokedServerCode;
  Object? revokePeerError;

  XrayClientResult? requestXrayClientResult;

  /// Holds [requestXrayClient] until completed: a request still in flight.
  Completer<void>? requestXrayClientGate;
  Object? requestXrayClientError;
  int requestXrayClientCalls = 0;
  String? lastXrayRequestedServerCode;
  String? lastXrayRequestedProfileCode;

  int revokeXrayClientCalls = 0;
  String? lastRevokedXrayServerCode;
  String? lastRevokedXrayProfileCode;
  Object? revokeXrayClientError;

  @override
  Future<List<AvailableServer>> listAvailableServers() async {
    final Object? error = listError;
    if (error != null) {
      throw error;
    }
    return servers;
  }

  @override
  Future<WireGuardPeerResult> requestPeer({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
    required String publicKey,
  }) async {
    requestPeerCalls++;
    lastRequestedServerCode = serverCode;
    lastRequestedProfileCode = protocolProfileCode;
    lastRequestedPublicKey = publicKey;
    await requestPeerGate?.future;
    final Object? error = requestPeerError;
    if (error != null) {
      throw error;
    }
    return requestPeerResult!;
  }

  @override
  Future<void> revokePeer({
    required String deviceId,
    required String serverCode,
  }) async {
    revokePeerCalls++;
    lastRevokedServerCode = serverCode;
    final Object? error = revokePeerError;
    if (error != null) {
      throw error;
    }
  }

  @override
  Future<XrayClientResult> requestXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    requestXrayClientCalls++;
    lastXrayRequestedServerCode = serverCode;
    lastXrayRequestedProfileCode = protocolProfileCode;
    await requestXrayClientGate?.future;
    final Object? error = requestXrayClientError;
    if (error != null) {
      throw error;
    }
    return requestXrayClientResultFor?.call(protocolProfileCode) ??
        requestXrayClientResult!;
  }

  /// A credential per profile, where one test needs different transports.
  XrayClientResult? Function(String profileCode)? requestXrayClientResultFor;

  @override
  Future<void> revokeXrayClient({
    required String deviceId,
    required String serverCode,
    required String protocolProfileCode,
  }) async {
    revokeXrayClientCalls++;
    lastRevokedXrayServerCode = serverCode;
    lastRevokedXrayProfileCode = protocolProfileCode;
    final Object? error = revokeXrayClientError;
    if (error != null) {
      throw error;
    }
  }
}
